#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include "crypto_api.h"
#include "aes.h"
#include "sha512.h"
#include "hmac_sha512.h"
#include "kdf.h"
#include "file_crypto.h"
#include "platform_utils.h"
#include "error_utils.h"
#include "password_utils.h"
#include "key_derivation.h"
#include "random_utils.h"
#include "file_path_utils.h"


#ifdef PLATFORM_WINDOWS
#include <windows.h>
#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
#endif

// 청크 크기 정의 (1MB - 성능 최적화)
#define FILE_CHUNK_SIZE (1024 * 1024)

// 로깅 헬퍼 함수들 (다른 함수들보다 먼저 정의)

/**
 * @brief 에러 메시지를 출력합니다.
 * @param show_error 출력 여부 (0이면 출력하지 않음)
 * @param format printf 형식 문자열
 * @param ... 가변 인자 (format에 맞는 값들)
 * @note [ERROR] 접두사가 자동으로 추가됩니다.
 */
static void log_error(int show_error, const char* format, ...) {
    if (!show_error) return;
    
    va_list args;
    va_start(args, format);
    printf("[ERROR] ");
    vprintf(format, args);
    va_end(args);
}

/**
 * @brief 정보 메시지를 출력합니다.
 * @param show_error 출력 여부 (0이면 출력하지 않음)
 * @param format printf 형식 문자열
 * @param ... 가변 인자 (format에 맞는 값들)
 */
static void log_info(int show_error, const char* format, ...) {
    if (!show_error) return;
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

/**
 * @brief 사용자로부터 문자열 입력을 받습니다.
 * @param prompt 입력 프롬프트 메시지
 * @param buffer 입력을 저장할 버퍼
 * @param buffer_size 버퍼 크기
 * @param scanf_format scanf 형식 문자열 (예: SCANF_PATH_FORMAT)
 * @param error_msg 에러 발생 시 출력할 메시지
 * @return 1 성공, 0 실패
 */
static int read_input_string(const char* prompt, char* buffer, size_t buffer_size,
                             const char* scanf_format, const char* error_msg) {
    if (!prompt || !buffer || buffer_size == 0 || !scanf_format || !error_msg) {
        log_error(1, "Internal error: Invalid parameters for read_input_string.\n");
        return 0;
    }
    
    printf("%s", prompt);
    if (scanf(scanf_format, buffer) != 1) {
        log_error(1, "%s", error_msg);
        return 0;
    }
    return 1;
}

/**
 * @brief 사용자로부터 정수 입력을 받고 범위를 검증합니다.
 * @param prompt 입력 프롬프트 메시지
 * @param value 입력받은 정수를 저장할 포인터
 * @param min 최소값
 * @param max 최대값
 * @param error_msg 에러 발생 시 출력할 메시지
 * @return 1 성공, 0 실패
 */
static int read_input_int(const char* prompt, int* value, int min, int max, const char* error_msg) {
    if (!prompt || !value || !error_msg) {
        log_error(1, "Internal error: Invalid parameters for read_input_int.\n");
        return 0;
    }
    
    printf("%s", prompt);
    if (scanf("%d", value) != 1 || *value < min || *value > max) {
        log_error(1, "%s", error_msg);
        return 0;
    }
    return 1;
}

/**
 * @brief 암호화/복호화 성공 결과를 출력합니다.
 * @param operation 작업 타입 ("encrypt" 또는 "decrypt")
 * @param output_path 출력 파일 경로
 */
static void print_operation_success(const char* operation, const char* output_path) {
    if (strcmp(operation, "encrypt") == 0) {
        printf("File encryption and HMAC generation succeeded.\n");
        printf("Encrypted file: %s\n", output_path);
    } else if (strcmp(operation, "decrypt") == 0) {
        printf("Integrity verified. File decryption succeeded.\n");
        printf("Decrypted file: %s\n", output_path);
    }
}

/**
 * @brief 진행률을 콘솔에 표시합니다.
 * @param processed 처리된 바이트 수
 * @param total 전체 바이트 수
 * @param operation 작업 이름 (예: "Encrypting", "Decrypting")
 * @note 진행률 바와 퍼센트를 실시간으로 업데이트합니다.
 */
static void print_progress(long processed, long total, const char* operation) {
    if (total <= 0) return;
    
    double percent = (double)processed / total * 100.0;
    if (percent > 100.0) percent = 100.0;
    
    // Progress bar 길이 (50자)
    int bar_width = 50;
    int filled = (int)(percent / 100.0 * bar_width);
    
    printf("\r%s [", operation);
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) {
            printf("=");
        } else if (i == filled) {
            printf(">");
        } else {
            printf(" ");
        }
    }
    printf("] %.1f%% (%ld / %ld bytes)", percent, processed, total);
    fflush(stdout);
}

/**
 * @brief 진행률을 업데이트합니다 (콜백 또는 print_progress 사용).
 * @param processed 처리된 바이트 수
 * @param total 전체 바이트 수
 * @param progress_cb 진행률 콜백 함수 (NULL이면 print_progress 사용)
 * @param user_data 콜백에 전달할 사용자 데이터
 * @param operation 작업 이름 (예: "Encrypting", "Decrypting")
 * @param update_interval 업데이트 간격 (퍼센트 단위, 0이면 매 퍼센트마다)
 * @note 콜백이 있으면 콜백을 호출하고, 없으면 print_progress를 사용합니다.
 */
static void update_progress_with_callback(long processed, long total,
                                          progress_callback_t progress_cb, void* user_data,
                                          const char* operation, int update_interval) {
    if (progress_cb) {
        // 콜백이 있으면 콜백 사용
        progress_cb(processed, total, user_data);
    } else {
        // 콜백이 없으면 print_progress 사용 (간격 제어)
        static long last_percent_encrypt = -1;
        static long last_percent_decrypt = -1;
        
        // operation에 따라 다른 static 변수 사용
        long* last_percent = (strcmp(operation, "Encrypting") == 0) ? 
                            &last_percent_encrypt : &last_percent_decrypt;
        
        long current_percent = (long)((processed * 100LL) / total);
        long remaining = total - processed;
        
        // 업데이트 간격에 따라 출력 조건 결정
        int should_update = 0;
        if (update_interval > 0) {
            // 지정된 간격(예: 2%) 단위로 출력
            should_update = (current_percent != *last_percent && 
                            (current_percent % update_interval == 0 || 
                             current_percent == 100 || 
                             remaining < FILE_CHUNK_SIZE));
        } else {
            // 간격이 0이면 퍼센트 변경 시마다 또는 마지막 청크 전에 출력
            should_update = (current_percent != *last_percent || remaining < FILE_CHUNK_SIZE);
        }
        
        if (should_update) {
            print_progress(processed, total, operation);
            *last_percent = current_percent;
        }
    }
}

/**
 * @brief 암호화 파일 헤더를 생성합니다.
 * @param input_path 입력 파일 경로 (확장자 추출용)
 * @param aes_key_bits AES 키 길이 (128, 192, 256)
 * @param salt PBKDF2 salt (16바이트)
 * @param nonce CTR 모드 nonce (8바이트)
 * @param header 출력 헤더 구조체
 * @return FILE_CRYPTO_SUCCESS 성공, FILE_CRYPTO_ERR_INVALID_INPUT 파라미터 오류
 */
static FILE_CRYPTO_STATUS create_encryption_header(const char* input_path, int aes_key_bits,
                                                    const uint8_t* salt, const uint8_t* nonce,
                                                    EncFileHeader* header) {
    if (!input_path || !salt || !nonce || !header) return FILE_CRYPTO_ERR_INVALID_INPUT;
    
    // 원본 파일 확장자 추출 및 헤더에 저장
    char original_ext[16];
    extract_extension(input_path, original_ext, sizeof(original_ext));
    size_t ext_len = strlen(original_ext);
    if (ext_len > 7) ext_len = 7; // 최대 7바이트 (format[8]에 널 종료 문자 공간 확보)
    
    // 헤더 작성
    memcpy(header->signature, ENC_SIGNATURE, 4);
    header->version = ENC_VERSION;
    header->key_length_code = (aes_key_bits == 128) ? KEY_LENGTH_CODE_128 : 
                             (aes_key_bits == 192) ? KEY_LENGTH_CODE_192 : KEY_LENGTH_CODE_256;
    header->mode_code = ENC_MODE_CTR;
    header->hmac_enabled = ENC_HMAC_ENABLED;
    memcpy(header->nonce, nonce, 8);
    memset(header->format, 0, 8);
    // format에 확장자 문자열 저장 (예: ".hwp", ".png", ".jpeg", ".txt")
    if (ext_len > 0) {
        memcpy(header->format, original_ext, ext_len);
    }
    memcpy(header->salt, salt, ENC_SALT_SIZE);
    memset(header->reserved, 0, sizeof(header->reserved));
    
    return FILE_CRYPTO_SUCCESS;
}

/**
 * @brief 파일 내용을 암호화하고 출력 파일에 씁니다.
 * @param fin 입력 파일 포인터
 * @param fout 출력 파일 포인터
 * @param file_size 파일 크기 (바이트)
 * @param aes_ctx AES 암호화 컨텍스트
 * @param nonce_counter CTR 모드 nonce 카운터 (16바이트)
 * @param hmac_ctx HMAC 컨텍스트 (평문에 대해 업데이트)
 * @param progress_cb 진행률 콜백 함수 (NULL 가능)
 * @param user_data 콜백에 전달할 사용자 데이터
 * @return FILE_CRYPTO_SUCCESS 성공, 그 외 실패 시 에러 코드
 */
static FILE_CRYPTO_STATUS encrypt_file_content(FILE* fin, FILE* fout, long file_size,
                                                const AES_CTX* aes_ctx, uint8_t* nonce_counter,
                                                HMAC_SHA512_CTX* hmac_ctx,
                                                progress_callback_t progress_cb, void* user_data) {
    if (!fin || !fout || !aes_ctx || !nonce_counter || !hmac_ctx) return FILE_CRYPTO_ERR_INVALID_INPUT;
    
    uint8_t* buffer = (uint8_t*)malloc(FILE_CHUNK_SIZE);
    if (!buffer) return FILE_CRYPTO_ERR_MEMORY_ALLOCATION;
    
    size_t bytes_read;
    long total_processed = 0;
    FILE_CRYPTO_STATUS result = FILE_CRYPTO_SUCCESS;
    
    // 파일 위치를 처음으로
    if (fseek(fin, 0, SEEK_SET) != 0) {
        free(buffer);
        return FILE_CRYPTO_ERR_FILE_READ;
    }
    
    while ((bytes_read = fread(buffer, 1, FILE_CHUNK_SIZE, fin)) > 0) {
        // HMAC 업데이트 (평문에 대해 - 암호화 전)
        hmac_sha512_update(hmac_ctx, buffer, bytes_read);
        
        // 동시에 암호화 (in-place)
        if (AES_CTR_crypt(aes_ctx, buffer, bytes_read, buffer, nonce_counter) != CRYPTO_SUCCESS) {
            free(buffer);
            return FILE_CRYPTO_ERR_ENCRYPTION_FAILED;
        }
        
        // 암호문 쓰기
        if (fwrite(buffer, 1, bytes_read, fout) != bytes_read) {
            free(buffer);
            return FILE_CRYPTO_ERR_FILE_WRITE;
        }
        
        // 진행률 업데이트 - 콜백이 있으면 콜백, 없으면 print_progress
        total_processed += bytes_read;
        update_progress_with_callback(total_processed, file_size, progress_cb, user_data,
                                     "Encrypting", 2);  // 2% 단위로 출력 (성능 최적화)
    }
    
    // 파일 읽기 중 오류 확인
    if (ferror(fin)) {
        free(buffer);
        return FILE_CRYPTO_ERR_FILE_READ;
    }
    
    free(buffer);
    return result;
}

/**
 * @brief HMAC을 파일의 지정된 위치에 씁니다.
 * @param fout 출력 파일 포인터
 * @param hmac_position HMAC을 쓸 파일 위치 (바이트 오프셋)
 * @param hmac HMAC 값 (64바이트)
 * @return FILE_CRYPTO_SUCCESS 성공, FILE_CRYPTO_ERR_FILE_WRITE 쓰기 실패
 * @note 파일 포인터를 원래 위치로 복원합니다.
 */
static FILE_CRYPTO_STATUS write_hmac_to_file(FILE* fout, long hmac_position, 
                                              const uint8_t* hmac) {
    if (!fout || !hmac) return FILE_CRYPTO_ERR_INVALID_INPUT;
    
    long current_pos = ftell(fout);
    if (current_pos < 0) {
        if (ferror(fout)) {
            return FILE_CRYPTO_ERR_FILE_WRITE;
        }
        return FILE_CRYPTO_ERR_FILE_WRITE;
    }
    if (fseek(fout, hmac_position, SEEK_SET) != 0) {
        return FILE_CRYPTO_ERR_FILE_WRITE;
    }
    size_t written = fwrite(hmac, 1, ENC_HMAC_SIZE, fout);
    if (fseek(fout, current_pos, SEEK_SET) != 0) {  // 원래 위치로 복귀
        return FILE_CRYPTO_ERR_FILE_WRITE;
    }
    
    return (written == ENC_HMAC_SIZE) ? FILE_CRYPTO_SUCCESS : FILE_CRYPTO_ERR_FILE_WRITE;
}

/**
 * @brief 파일 암호화 내부 구현 함수 (진행률 콜백 지원).
 * @param input_path 입력 파일 경로
 * @param output_path 출력 파일 경로
 * @param aes_key_bits AES 키 길이 (128, 192, 256)
 * @param password 비밀번호
 * @param progress_cb 진행률 콜백 함수 (NULL 가능)
 * @param user_data 콜백에 전달할 사용자 데이터
 * @return 1 성공, 0 실패
 */
static int encrypt_file_internal(const char* input_path, const char* output_path,
                                 int aes_key_bits, const char* password,
                                 progress_callback_t progress_cb, void* user_data) {
    FILE* fin = platform_fopen(input_path, "rb");
    if (!fin) {
        log_error(!progress_cb, "Cannot open file: %s\n", input_path);
        return 0;
    }
    
    // 파일 버퍼링 최적화 (모든 플랫폼)
    setvbuf(fin, NULL, _IOFBF, FILE_BUFFER_SIZE);
    
    // 파일 크기 확인
    if (fseek(fin, 0, SEEK_END) != 0) {
        fclose(fin);
        log_error(!progress_cb, "Cannot seek to end of file.\n");
        return 0;  // FILE_CRYPTO_ERR_FILE_READ
    }
    long file_size = ftell(fin);
    if (file_size < 0) {
        fclose(fin);
        if (ferror(fin)) {
            log_error(!progress_cb, "Error occurred while determining file size.\n");
        } else {
            log_error(!progress_cb, "Cannot determine file size.\n");
        }
        return 0;  // FILE_CRYPTO_ERR_FILE_SIZE
    }
    if (fseek(fin, 0, SEEK_SET) != 0) {
        fclose(fin);
        log_error(!progress_cb, "Cannot seek to beginning of file.\n");
        return 0;  // FILE_CRYPTO_ERR_FILE_READ
    }
    
    log_info(!progress_cb, "Encrypting...\n");
    
    // Salt 생성 (PBKDF2용)
    uint8_t salt[ENC_SALT_SIZE];
    generate_salt(salt, sizeof(salt));
    
    // 키 도출
    uint8_t aes_key[32];
    uint8_t hmac_key[HMAC_KEY_SIZE];
    derive_keys(password, aes_key_bits, salt, sizeof(salt), aes_key, hmac_key);
    
    // AES 컨텍스트 설정
    AES_CTX aes_ctx;
    if (AES_set_key(&aes_ctx, aes_key, aes_key_bits) != CRYPTO_SUCCESS) {
        fclose(fin);
        return 0;
    }
    
    // Nonce 생성
    uint8_t nonce[8];
    generate_nonce(nonce, 8);
    
    // CTR 모드용 nonce_counter (8바이트 nonce + 8바이트 카운터)
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, nonce, 8);
    memset(nonce_counter + 8, 0, 8);
    
    // 헤더 생성
    EncFileHeader header;
    FILE_CRYPTO_STATUS header_result = create_encryption_header(input_path, aes_key_bits, salt, nonce, &header);
    if (header_result != FILE_CRYPTO_SUCCESS) {
        fclose(fin);
        return 0;  // header_result에 상세 에러 정보 포함
    }
    
    // HMAC 초기화 (헤더 + 원본 파일로 생성)
    HMAC_SHA512_CTX hmac_ctx;
    hmac_sha512_init(&hmac_ctx, hmac_key, HMAC_KEY_SIZE);
    hmac_sha512_update(&hmac_ctx, (uint8_t*)&header, sizeof(header));  // 헤더를 HMAC에 포함
    
    // 출력 파일 작성
    FILE* fout = platform_fopen(output_path, "wb");
    if (!fout) {
        fclose(fin);
        return 0;  // FILE_CRYPTO_ERR_FILE_OPEN (출력 파일)
    }
    
    // 파일 버퍼링 최적화 (모든 플랫폼)
    setvbuf(fout, NULL, _IOFBF, FILE_BUFFER_SIZE);
    
    // 헤더 쓰기
    if (fwrite(&header, 1, sizeof(header), fout) != sizeof(header)) {
        fclose(fin);
        fclose(fout);
        log_error(!progress_cb, "Failed to write file header.\n");
        return 0;  // FILE_CRYPTO_ERR_FILE_WRITE
    }
    
    // HMAC을 위한 임시 공간 (나중에 쓸 예정)
    long hmac_position = ftell(fout);
    if (hmac_position < 0) {
        fclose(fin);
        fclose(fout);
        log_error(!progress_cb, "Cannot determine HMAC position.\n");
        return 0;  // FILE_CRYPTO_ERR_FILE_WRITE
    }
    uint8_t hmac_placeholder[ENC_HMAC_SIZE] = {0};
    if (fwrite(hmac_placeholder, 1, ENC_HMAC_SIZE, fout) != ENC_HMAC_SIZE) {
        fclose(fin);
        fclose(fout);
        log_error(!progress_cb, "Failed to write HMAC placeholder.\n");
        return 0;  // FILE_CRYPTO_ERR_FILE_WRITE
    }
    
    // 파일 내용 암호화 및 쓰기
    FILE_CRYPTO_STATUS encrypt_result = encrypt_file_content(fin, fout, file_size, &aes_ctx, nonce_counter, 
                                                             &hmac_ctx, progress_cb, user_data);
    
    // HMAC 최종 계산
    uint8_t hmac[ENC_HMAC_SIZE];
    hmac_sha512_final(&hmac_ctx, hmac);
    
    // HMAC을 올바른 위치에 쓰기
    if (encrypt_result == FILE_CRYPTO_SUCCESS) {
        FILE_CRYPTO_STATUS hmac_result = write_hmac_to_file(fout, hmac_position, hmac);
        if (hmac_result != FILE_CRYPTO_SUCCESS) {
            fclose(fin);
            fclose(fout);
            return 0;  // hmac_result에 상세 에러 정보 포함
        }
    } else {
        fclose(fin);
        fclose(fout);
        return 0;  // encrypt_result에 상세 에러 정보 포함
    }
    fclose(fin);
    
    fclose(fout);
    
    // 진행률 완료 표시
    if (progress_cb) {
        progress_cb(file_size, file_size, user_data);
    } else {
        print_progress(file_size, file_size, "Encrypting");
        log_info(!progress_cb, "Encryption completed!\n");
    }
    
    return 1;
}

/**
 * @brief 파일을 암호화합니다 (CLI용).
 * @param input_path 입력 파일 경로
 * @param output_path 출력 파일 경로
 * @param aes_key_bits AES 키 길이 (128, 192, 256)
 * @param password 비밀번호
 * @return 1 성공, 0 실패
 */
int encrypt_file(const char* input_path, const char* output_path,
                 int aes_key_bits, const char* password) {
    return encrypt_file_internal(input_path, output_path, aes_key_bits, password, NULL, NULL);
}

/**
 * @brief 파일을 암호화합니다 (GUI용, 진행률 콜백 지원).
 * @param input_path 입력 파일 경로
 * @param output_path 출력 파일 경로
 * @param aes_key_bits AES 키 길이 (128, 192, 256)
 * @param password 비밀번호
 * @param progress_cb 진행률 콜백 함수 (NULL 가능)
 * @param user_data 콜백에 전달할 사용자 데이터
 * @return 1 성공, 0 실패
 */
int encrypt_file_with_progress(const char* input_path, const char* output_path,
                               int aes_key_bits, const char* password,
                               progress_callback_t progress_cb, void* user_data) {
    return encrypt_file_internal(input_path, output_path, aes_key_bits, password, progress_cb, user_data);
}

/**
 * @brief 암호화 파일 헤더를 읽고 검증합니다.
 * @param fin 입력 파일 포인터
 * @param header 출력 헤더 구조체
 * @param file_size 출력 파일 크기 (바이트)
 * @param ciphertext_size 출력 암호문 크기 (바이트, 헤더와 HMAC 제외)
 * @param show_error 에러 메시지 출력 여부
 * @return FILE_CRYPTO_SUCCESS 성공, 그 외 실패 시 에러 코드
 */
static FILE_CRYPTO_STATUS read_and_validate_header(FILE* fin, EncFileHeader* header, long* file_size, 
                                                    long* ciphertext_size, int show_error) {
    if (!fin || !header || !file_size || !ciphertext_size) return FILE_CRYPTO_ERR_INVALID_INPUT;
    
    // 헤더 읽기
    if (fread(header, 1, sizeof(EncFileHeader), fin) != sizeof(EncFileHeader)) {
        log_error(show_error, "Cannot read file header.\n");
        return FILE_CRYPTO_ERR_INVALID_HEADER;
    }
    
    // 시그니처 검증
    if (memcmp(header->signature, ENC_SIGNATURE, 4) != 0) {
        log_error(show_error, "Invalid file format.\n");
        return FILE_CRYPTO_ERR_INVALID_SIGNATURE;
    }
    
    // 파일 크기 확인
    if (fseek(fin, 0, SEEK_END) != 0) {
        log_error(show_error, "Cannot seek to end of file.\n");
        return FILE_CRYPTO_ERR_FILE_READ;
    }
    *file_size = ftell(fin);
    if (*file_size < 0) {
        if (ferror(fin)) {
            log_error(show_error, "Error occurred while determining file size.\n");
        } else {
            log_error(show_error, "Cannot determine file size.\n");
        }
        return FILE_CRYPTO_ERR_FILE_SIZE;
    }
    
    // 헤더 다음에 HMAC이 있음
    long hmac_position = sizeof(EncFileHeader);
    *ciphertext_size = *file_size - sizeof(EncFileHeader) - ENC_HMAC_SIZE; // 헤더와 HMAC 제외
    
    if (*ciphertext_size <= 0) {
        log_error(show_error, "Invalid file size.\n");
        return FILE_CRYPTO_ERR_FILE_SIZE;
    }
    
    return FILE_CRYPTO_SUCCESS;
}

/**
 * @brief 암호화 메타데이터를 읽습니다 (HMAC, 키 길이, salt).
 * @param fin 입력 파일 포인터
 * @param header 암호화 파일 헤더
 * @param stored_hmac 출력 저장된 HMAC (64바이트)
 * @param aes_key_bits 출력 AES 키 길이 (128, 192, 256)
 * @param pbkdf2_salt 출력 PBKDF2 salt 포인터 (헤더 내부 참조)
 * @param pbkdf2_salt_len 출력 PBKDF2 salt 길이
 * @param show_error 에러 메시지 출력 여부
 * @return FILE_CRYPTO_SUCCESS 성공, 그 외 실패 시 에러 코드
 */
static FILE_CRYPTO_STATUS read_encryption_metadata(FILE* fin, const EncFileHeader* header,
                                                    uint8_t* stored_hmac, int* aes_key_bits,
                                                    const uint8_t** pbkdf2_salt, size_t* pbkdf2_salt_len,
                                                    int show_error) {
    if (!fin || !header || !stored_hmac || !aes_key_bits) return FILE_CRYPTO_ERR_INVALID_INPUT;
    
    // HMAC 읽기 (헤더 다음 위치)
    long hmac_position = sizeof(EncFileHeader);
    if (fseek(fin, hmac_position, SEEK_SET) != 0) {
        log_error(show_error, "Cannot seek to HMAC position.\n");
        return FILE_CRYPTO_ERR_FILE_READ;
    }
    if (fread(stored_hmac, 1, ENC_HMAC_SIZE, fin) != ENC_HMAC_SIZE) {
        log_error(show_error, "Cannot read HMAC.\n");
        return FILE_CRYPTO_ERR_FILE_READ;
    }
    
    // AES 키 길이 결정
    if (header->key_length_code == KEY_LENGTH_CODE_128) *aes_key_bits = 128;
    else if (header->key_length_code == KEY_LENGTH_CODE_192) *aes_key_bits = 192;
    else if (header->key_length_code == KEY_LENGTH_CODE_256) *aes_key_bits = 256;
    else {
        log_error(show_error, "Unsupported AES key length.\n");
        return FILE_CRYPTO_ERR_UNSUPPORTED_KEY_LENGTH;
    }
    
    // PBKDF2 salt 결정 (v2 이상은 헤더에 저장된 salt 사용)
    if (pbkdf2_salt && pbkdf2_salt_len) {
        *pbkdf2_salt = NULL;
        *pbkdf2_salt_len = 0;
        if (header->version >= 0x02) {
            *pbkdf2_salt = header->salt;
            *pbkdf2_salt_len = ENC_SALT_SIZE;
        }
    }
    
    return FILE_CRYPTO_SUCCESS;
}

/**
 * @brief 파일 내용을 복호화하고 임시 파일에 저장합니다.
 * @param fin 입력 파일 포인터 (암호문)
 * @param ftemp 임시 파일 포인터 (복호화된 평문)
 * @param ciphertext_size 암호문 크기 (바이트)
 * @param aes_ctx AES 복호화 컨텍스트
 * @param nonce_counter CTR 모드 nonce 카운터 (16바이트)
 * @param buffer 작업용 버퍼 (최소 FILE_CHUNK_SIZE 크기)
 * @param progress_cb 진행률 콜백 함수 (NULL 가능)
 * @param user_data 콜백에 전달할 사용자 데이터
 * @param show_error 에러 메시지 출력 여부
 * @return FILE_CRYPTO_SUCCESS 성공, 그 외 실패 시 에러 코드
 */
static FILE_CRYPTO_STATUS decrypt_file_content(FILE* fin, FILE* ftemp, long ciphertext_size,
                                                const AES_CTX* aes_ctx, uint8_t* nonce_counter,
                                                uint8_t* buffer,
                                                progress_callback_t progress_cb, void* user_data,
                                                int show_error) {
    if (!fin || !ftemp || !aes_ctx || !nonce_counter || !buffer) return FILE_CRYPTO_ERR_INVALID_INPUT;
    
    // 암호문 위치로 이동 (헤더 + HMAC 다음)
    if (fseek(fin, sizeof(EncFileHeader) + ENC_HMAC_SIZE, SEEK_SET) != 0) {
        log_error(show_error, "Cannot seek to ciphertext position.\n");
        return FILE_CRYPTO_ERR_FILE_READ;
    }
    
    size_t bytes_read;
    long total_read = 0;
    FILE_CRYPTO_STATUS result = FILE_CRYPTO_SUCCESS;
    
    while (total_read < ciphertext_size) {
        size_t to_read = (ciphertext_size - total_read < FILE_CHUNK_SIZE) ? 
                         (ciphertext_size - total_read) : FILE_CHUNK_SIZE;
        bytes_read = fread(buffer, 1, to_read, fin);
        
        // EOF 또는 에러 확인
        if (bytes_read == 0) {
            if (ferror(fin)) {
                log_error(show_error, "File read error.\n");
                return FILE_CRYPTO_ERR_FILE_READ;
            }
            // EOF에 도달했는데 아직 읽어야 할 데이터가 남아있으면 에러
            if (total_read < ciphertext_size) {
                log_error(show_error, "Unexpected end of file. Expected %ld bytes, read %ld bytes.\n", 
                         ciphertext_size, total_read);
                return FILE_CRYPTO_ERR_FILE_READ;
            }
            break;  // 정상 종료
        }
        
        // 청크 복호화 (in-place)
        if (AES_CTR_crypt(aes_ctx, buffer, bytes_read, buffer, nonce_counter) != CRYPTO_SUCCESS) {
            log_error(show_error, "Decryption failed.\n");
            return FILE_CRYPTO_ERR_DECRYPTION_FAILED;
        }
        
        // 복호화된 평문을 임시 파일에 저장
        if (fwrite(buffer, 1, bytes_read, ftemp) != bytes_read) {
            log_error(show_error, "Failed to write to temporary file.\n");
            return FILE_CRYPTO_ERR_FILE_WRITE;
        }
        
        total_read += bytes_read;
        
        // 진행률 업데이트 - 콜백이 있으면 콜백, 없으면 print_progress
        update_progress_with_callback(total_read, ciphertext_size, progress_cb, user_data,
                                     "Decrypting", 0);  // 0 = 퍼센트 변경 시마다 출력 (더 자주 업데이트)
    }
    
    // 루프 종료 후 검증: 모든 데이터를 읽었는지 확인
    if (total_read != ciphertext_size) {
        log_error(show_error, "Incomplete decryption. Expected %ld bytes, read %ld bytes.\n", 
                 ciphertext_size, total_read);
        return FILE_CRYPTO_ERR_FILE_READ;
    }
    
    // 완료 시 항상 100% 진행률 출력 (성공하고 모든 데이터를 읽었을 때만)
    if (total_read == ciphertext_size && !progress_cb) {
        print_progress(ciphertext_size, ciphertext_size, "Decrypting");
    }
    
    return result;  // 성공/실패 반환 (버퍼는 호출자가 관리)
}

/**
 * @brief HMAC을 검증합니다 (헤더 + 복호화된 평문).
 * @param ftemp 임시 파일 포인터 (복호화된 평문)
 * @param header 암호화 파일 헤더
 * @param hmac_key HMAC 키 (24바이트)
 * @param stored_hmac 저장된 HMAC (64바이트)
 * @param buffer 작업용 버퍼 (최소 FILE_CHUNK_SIZE 크기)
 * @param show_error 에러 메시지 출력 여부
 * @return FILE_CRYPTO_SUCCESS 성공, FILE_CRYPTO_ERR_HMAC_VERIFICATION_FAILED 검증 실패
 */
static FILE_CRYPTO_STATUS verify_file_hmac(FILE* ftemp, const EncFileHeader* header,
                                           const uint8_t* hmac_key, const uint8_t* stored_hmac,
                                           uint8_t* buffer, int show_error) {
    if (!ftemp || !header || !hmac_key || !stored_hmac || !buffer) return FILE_CRYPTO_ERR_INVALID_INPUT;
    
    // HMAC 검증: 헤더 + 복호화한 평문으로 HMAC 생성
    HMAC_SHA512_CTX hmac_ctx;
    hmac_sha512_init(&hmac_ctx, hmac_key, HMAC_KEY_SIZE);
    hmac_sha512_update(&hmac_ctx, (uint8_t*)header, sizeof(EncFileHeader));  // 헤더를 HMAC에 포함
    
    // 임시 파일에서 복호화된 평문을 읽으면서 HMAC 업데이트
    if (fseek(ftemp, 0, SEEK_SET) != 0) {
        log_error(show_error, "Cannot seek to beginning of temporary file.\n");
        return FILE_CRYPTO_ERR_FILE_READ;
    }
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, FILE_CHUNK_SIZE, ftemp)) > 0) {
        hmac_sha512_update(&hmac_ctx, buffer, bytes_read);
    }
    
    // HMAC 최종 계산
    uint8_t computed_hmac[ENC_HMAC_SIZE];
    hmac_sha512_final(&hmac_ctx, computed_hmac);
    
    // HMAC 검증
    if (memcmp(stored_hmac, computed_hmac, ENC_HMAC_SIZE) != 0) {
        log_error(show_error, "HMAC integrity verification failed. File may be corrupted or password is incorrect.\n");
        return FILE_CRYPTO_ERR_HMAC_VERIFICATION_FAILED;
    }
    
    log_info(show_error, "HMAC verification succeeded! Integrity confirmed.\n");
    return FILE_CRYPTO_SUCCESS;
}

/**
 * @brief 복호화된 파일을 최종 경로에 씁니다 (원본 확장자 복원).
 * @param ftemp 임시 파일 포인터 (복호화된 평문)
 * @param output_path 출력 파일 경로 (기본 경로)
 * @param header 암호화 파일 헤더 (확장자 정보 포함)
 * @param final_output_path 출력 최종 파일 경로 (확장자 포함)
 * @param final_path_size final_output_path 버퍼 크기
 * @param buffer 작업용 버퍼 (최소 FILE_CHUNK_SIZE 크기)
 * @param show_error 에러 메시지 출력 여부
 * @param progress_cb 진행률 콜백 함수 (GUI 모드 확인용, NULL 가능)
 * @return FILE_CRYPTO_SUCCESS 성공, 그 외 실패 시 에러 코드
 */
static FILE_CRYPTO_STATUS write_decrypted_file(FILE* ftemp, const char* output_path,
                                                const EncFileHeader* header, char* final_output_path,
                                                size_t final_path_size, uint8_t* buffer, int show_error,
                                                progress_callback_t progress_cb) {
    if (!ftemp || !output_path || !header || !buffer) return FILE_CRYPTO_ERR_INVALID_INPUT;
    
    // 헤더에서 원본 확장자 읽기
    char format_ext[16] = {0};
    strncpy(format_ext, (const char*)header->format, 8);
    format_ext[8] = '\0';
    size_t ext_len = strlen(format_ext);
    
    // 출력 파일 경로에 확장자 추가
    char actual_output_path[512];
    strncpy(actual_output_path, output_path, sizeof(actual_output_path) - 1);
    actual_output_path[sizeof(actual_output_path) - 1] = '\0';
    
    if (ext_len > 0) {
        // 출력 경로에 확장자가 없으면 추가
        char* last_dot = strrchr(actual_output_path, '.');
        const char* last_slash = platform_find_last_separator(actual_output_path);
        if (!last_dot || (last_slash && last_dot < last_slash)) {
            // 확장자가 없으면 추가
            size_t path_len = strlen(actual_output_path);
            if (path_len + ext_len < sizeof(actual_output_path)) {
                strncpy(actual_output_path + path_len, format_ext, ext_len);
                actual_output_path[path_len + ext_len] = '\0';
            }
        }
    }
    
    // 실제 저장된 파일 경로를 반환
    if (final_output_path && final_path_size > 0) {
        strncpy(final_output_path, actual_output_path, final_path_size - 1);
        final_output_path[final_path_size - 1] = '\0';
    }
    
    // 출력 파일 작성
    FILE* fout = platform_fopen(actual_output_path, "wb");
    if (!fout) {
        if (progress_cb != NULL) {
            format_error_message(final_output_path, final_path_size, "Cannot create output file", 1);
        }
        return FILE_CRYPTO_ERR_FILE_OPEN;
    }
    
    // 출력 파일 버퍼링 최적화 (모든 플랫폼)
    setvbuf(fout, NULL, _IOFBF, FILE_BUFFER_SIZE);
    
    // 임시 파일에서 복호화된 평문을 최종 출력 파일로 복사
    if (fseek(ftemp, 0, SEEK_SET) != 0) {
        fclose(fout);
        log_error(show_error, "Cannot seek to beginning of temporary file.\n");
        return FILE_CRYPTO_ERR_FILE_READ;
    }
    size_t bytes_read;
    long total_read = 0;
    
    while ((bytes_read = fread(buffer, 1, FILE_CHUNK_SIZE, ftemp)) > 0) {
        if (fwrite(buffer, 1, bytes_read, fout) != bytes_read) {
            fclose(fout);
            remove(actual_output_path);
            if (progress_cb != NULL) {
                format_error_message(final_output_path, final_path_size, "Failed while writing decrypted file", 1);
            }
            return FILE_CRYPTO_ERR_FILE_WRITE;
        }
        total_read += bytes_read;
    }
    
    fclose(fout);
    return FILE_CRYPTO_SUCCESS;
}

/**
 * @brief 암호화 파일 헤더에서 AES 키 길이를 읽습니다 (복호화 전 확인용).
 * @param input_path 입력 파일 경로
 * @return AES 키 길이 (128, 192, 256), 실패 시 0
 */
int read_aes_key_length(const char* input_path) {
    FILE* fin = platform_fopen(input_path, "rb");
    if (!fin) {
        return 0;
    }
    
    EncFileHeader header;
    if (fread(&header, 1, sizeof(header), fin) != sizeof(header)) {
        fclose(fin);
        return 0;
    }
    
    fclose(fin);
    
    // 시그니처 검증
    if (memcmp(header.signature, ENC_SIGNATURE, 4) != 0) {
        return 0;
    }
    
    // 키 길이 코드에서 실제 키 길이 반환
    if (header.key_length_code == KEY_LENGTH_CODE_128) return 128;
    else if (header.key_length_code == KEY_LENGTH_CODE_192) return 192;
    else if (header.key_length_code == KEY_LENGTH_CODE_256) return 256;
    else return 0;
}

/**
 * @brief 파일 복호화 내부 구현 함수 (진행률 콜백 지원).
 * @param input_path 입력 파일 경로
 * @param output_path 출력 파일 경로 (기본 경로)
 * @param password 비밀번호
 * @param final_output_path 출력 최종 파일 경로 (확장자 포함)
 * @param final_path_size final_output_path 버퍼 크기
 * @param progress_cb 진행률 콜백 함수 (NULL 가능)
 * @param user_data 콜백에 전달할 사용자 데이터
 * @return 1 성공, 0 실패
 */
static int decrypt_file_internal(const char* input_path, const char* output_path,
                                  const char* password, char* final_output_path, size_t final_path_size,
                                  progress_callback_t progress_cb, void* user_data) {
    FILE* fin = platform_fopen(input_path, "rb");
    if (!fin) {
        log_error(!progress_cb, "Cannot open file: %s\n", input_path);
        return 0;
    }
    
    // 파일 버퍼링 최적화 (모든 플랫폼)
    setvbuf(fin, NULL, _IOFBF, FILE_BUFFER_SIZE);
    
    // 헤더 읽기 및 검증
    EncFileHeader header;
    long file_size, ciphertext_size;
    int show_error = (progress_cb == NULL);
    
    FILE_CRYPTO_STATUS header_result = read_and_validate_header(fin, &header, &file_size, &ciphertext_size, show_error);
    if (header_result != FILE_CRYPTO_SUCCESS) {
        fclose(fin);
        return 0;  // header_result에 상세 에러 정보 포함
    }
    
    // 암호화 메타데이터 읽기 (HMAC, 키 길이, salt)
    uint8_t stored_hmac[ENC_HMAC_SIZE];
    int aes_key_bits;
    const uint8_t* pbkdf2_salt = NULL;
    size_t pbkdf2_salt_len = 0;
    
    FILE_CRYPTO_STATUS metadata_result = read_encryption_metadata(fin, &header, stored_hmac, &aes_key_bits, 
                                                                 &pbkdf2_salt, &pbkdf2_salt_len, show_error);
    if (metadata_result != FILE_CRYPTO_SUCCESS) {
        fclose(fin);
        return 0;  // metadata_result에 상세 에러 정보 포함
    }
    
    // 키 도출
    uint8_t aes_key[32];
    uint8_t hmac_key[HMAC_KEY_SIZE];
    derive_keys(password, aes_key_bits, pbkdf2_salt, pbkdf2_salt_len, aes_key, hmac_key);
    
    // AES 컨텍스트 설정
    AES_CTX aes_ctx;
    if (AES_set_key(&aes_ctx, aes_key, aes_key_bits) != CRYPTO_SUCCESS) {
        fclose(fin);
        return 0;  // FILE_CRYPTO_ERR_DECRYPTION_FAILED (AES 키 설정 실패)
    }
    
    // CTR 모드용 nonce_counter
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, header.nonce, 8);
    memset(nonce_counter + 8, 0, 8);
    
    log_info(!progress_cb, "Decrypting...\n");
    
    // 임시 파일에 복호화된 평문 저장 (HMAC 검증을 위해)
    char temp_file_path[512];
    FILE* ftemp = platform_create_temp_file(temp_file_path, sizeof(temp_file_path));
    if (!ftemp) {
        fclose(fin);
        if (progress_cb != NULL) format_error_message(final_output_path, final_path_size, "Cannot create temporary file", 1);
        log_error(show_error, "Cannot create temporary file.\n");
        return 0;  // FILE_CRYPTO_ERR_TEMP_FILE_CREATE
    }
    
    // 임시 파일 버퍼링 최적화 (모든 플랫폼)
    setvbuf(ftemp, NULL, _IOFBF, FILE_BUFFER_SIZE);
    
    // 암호문 읽기 및 복호화를 위한 버퍼 할당
    uint8_t* buffer = (uint8_t*)malloc(FILE_CHUNK_SIZE);
    if (!buffer) {
        fclose(fin);
        fclose(ftemp);
        platform_delete_file(temp_file_path);
        return 0;  // FILE_CRYPTO_ERR_MEMORY_ALLOCATION
    }
    
    // 파일 내용 복호화
    FILE_CRYPTO_STATUS decrypt_result = decrypt_file_content(fin, ftemp, ciphertext_size, &aes_ctx, nonce_counter,
                                                              buffer, progress_cb, user_data, show_error);
    
    fclose(fin);
    
    if (decrypt_result != FILE_CRYPTO_SUCCESS) {
        free(buffer);
        fclose(ftemp);
        platform_delete_file(temp_file_path);
        if (progress_cb != NULL) format_error_message(final_output_path, final_path_size, "Decryption failed before HMAC verification", 0);
        log_error(show_error, "Decryption failed!\n");
        return 0;  // decrypt_result에 상세 에러 정보 포함
    }
    
    log_info(show_error, "Decryption completed! Verifying HMAC...\n");
    
    // HMAC 검증
    FILE_CRYPTO_STATUS hmac_result = verify_file_hmac(ftemp, &header, hmac_key, stored_hmac, buffer, show_error);
    if (hmac_result != FILE_CRYPTO_SUCCESS) {
        free(buffer);
        fclose(ftemp);
        platform_delete_file(temp_file_path);
        if (progress_cb != NULL) format_error_message(final_output_path, final_path_size, "HMAC integrity verification failed", 0);
        return 0;  // hmac_result에 상세 에러 정보 포함
    }
    
    // 복호화된 파일 쓰기
    FILE_CRYPTO_STATUS write_result = write_decrypted_file(ftemp, output_path, &header, final_output_path, 
                                                          final_path_size, buffer, show_error, progress_cb);
    if (write_result != FILE_CRYPTO_SUCCESS) {
        free(buffer);
        fclose(ftemp);
        platform_delete_file(temp_file_path);
        return 0;  // write_result에 상세 에러 정보 포함
    }
    
    free(buffer);
    fclose(ftemp);
    platform_delete_file(temp_file_path);
    
    // 진행률 완료 표시
    if (progress_cb) {
        progress_cb(ciphertext_size, ciphertext_size, user_data);
    } else {
        print_progress(ciphertext_size, ciphertext_size, "Decrypting");
        log_info(!progress_cb, "Decryption completed!\n");
    }
    
    return 1;
}

/**
 * @brief 파일을 복호화합니다 (CLI용).
 * @param input_path 입력 파일 경로
 * @param output_path 출력 파일 경로 (기본 경로)
 * @param password 비밀번호
 * @param final_output_path 출력 최종 파일 경로 (확장자 포함)
 * @param final_path_size final_output_path 버퍼 크기
 * @return 1 성공, 0 실패
 */
int decrypt_file(const char* input_path, const char* output_path,
                 const char* password, char* final_output_path, size_t final_path_size) {
    return decrypt_file_internal(input_path, output_path, password, final_output_path, final_path_size, NULL, NULL);
}

/**
 * @brief 파일을 복호화합니다 (GUI용, 진행률 콜백 지원).
 * @param input_path 입력 파일 경로
 * @param output_path 출력 파일 경로 (기본 경로)
 * @param password 비밀번호
 * @param final_output_path 출력 최종 파일 경로 (확장자 포함)
 * @param final_path_size final_output_path 버퍼 크기
 * @param progress_cb 진행률 콜백 함수 (NULL 가능)
 * @param user_data 콜백에 전달할 사용자 데이터
 * @return 1 성공, 0 실패
 */
int decrypt_file_with_progress(const char* input_path, const char* output_path,
                               const char* password, char* final_output_path, size_t final_path_size,
                               progress_callback_t progress_cb, void* user_data) {
    return decrypt_file_internal(input_path, output_path, password, final_output_path, final_path_size, progress_cb, user_data);
}

#ifndef BUILD_GUI
int main(void) {
    // OpenSSL 활성화 여부 확인 (런타임 체크)
    // crypto_random_bytes가 호출되면 자동으로 OpenSSL을 로드 시도함
#ifndef NDEBUG
    uint8_t test_buf[1];
    if (crypto_random_bytes(test_buf, 1) == CRYPTO_SUCCESS) {
        printf("OpenSSL enabled (loaded at runtime)\n");
    } else {
        printf("OpenSSL not available (will use fallback rand())\n");
    }
#endif
    
    // 시드 초기화 (프로그램 시작 시 한 번만)
    srand((unsigned int)time(NULL));
    
    int service;
    char file_path[MAX_PATH_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    int aes_choice;
    int aes_key_bits;
    
    printf("=======================================\n");
    printf("    File Encryption/Decryption Program \n");
    printf("=======================================\n\n");
    printf("Warning: File paths and filenames must not contain Korean characters.\n\n");
    
    // 서비스 선택
    printf("Enter service number:\n");
    printf("1. File Encryption\n");
    printf("2. File Decryption\n");
    while (!read_input_int("Choice: ", &service, 1, 2, "Invalid input. Please enter 1 or 2.\n")) {
        // 잘못된 입력 시 다시 시도
    }
    
    if (service == 1) {
        // 암호화
        if (!read_input_string("\nEnter file path to encrypt: ", file_path, sizeof(file_path),
                               SCANF_PATH_FORMAT, "Cannot read file path.\n")) {
            return 1;
        }
        
        // 입력 파일 존재 여부 확인
        if (!platform_file_exists(file_path)) {
            log_error(1, "File does not exist: %s\n", file_path);
            return 1;
        }
        
        printf("\nSelect AES for encryption:\n");
        printf("1. AES-128\n");
        printf("2. AES-192\n");
        printf("3. AES-256\n");
        while (!read_input_int("Choice: ", &aes_choice, 1, 3, "Invalid choice. Please enter 1, 2, or 3.\n")) {
            // 잘못된 입력 시 다시 시도
        }
        
        aes_key_bits = (aes_choice == 1) ? 128 : (aes_choice == 2) ? 192 : 256;
        printf("\nStarting file encryption with AES-%d-CTR.\n", aes_key_bits);
        
        if (!read_input_string("Enter password (alphanumeric, case-sensitive, max 10 chars): ",
                               password, sizeof(password), SCANF_PASSWORD_FORMAT,
                               "Cannot read password.\n")) {
            return 1;
        }
        
        if (!validate_password(password)) {
            log_error(1, "Password must be alphanumeric (case-sensitive) with maximum 10 characters.\n");
            return 1;
        }
        
        // 저장할 경로 입력
        char save_path[MAX_PATH_LENGTH];
        if (!read_input_string("Enter path to save encrypted file (excluding filename): ", save_path, sizeof(save_path),
                               SCANF_PATH_FORMAT, "Cannot read save path.\n")) {
            return 1;
        }
        
        // 디렉토리 존재 여부 확인
        if (!platform_directory_exists(save_path)) {
            log_error(1, "Directory does not exist: %s\n", save_path);
            return 1;
        }
        
        // 파일 이름 입력
        char file_name[MAX_FILENAME_LENGTH];
        if (!read_input_string("Enter encrypted file name (.enc extension will be added automatically): ",
                               file_name, sizeof(file_name), SCANF_FILENAME_FORMAT,
                               "Cannot read file name.\n")) {
            return 1;
        }
        
        // 최종 출력 경로 생성 (경로 + 파일명 + .enc)
        char output_path[MAX_PATH_LENGTH];
        build_output_path(output_path, sizeof(output_path), save_path, file_name, ".enc");
        
        if (encrypt_file(file_path, output_path, aes_key_bits, password)) {
            print_operation_success("encrypt", output_path);
        } else {
            log_error(1, "File encryption failed.\n");
            return 1;
        }
        
    } else if (service == 2) {
        // 복호화
        if (!read_input_string("\nEnter file path to decrypt: ", file_path, sizeof(file_path),
                               SCANF_PATH_FORMAT, "Cannot read file path.\n")) {
            return 1;
        }
        
        // 입력 파일 존재 여부 확인
        if (!platform_file_exists(file_path)) {
            log_error(1, "File does not exist: %s\n", file_path);
            return 1;
        }
        
        // 헤더에서 AES 키 길이 읽기
        int aes_key_bits = read_aes_key_length(file_path);
        if (aes_key_bits == 0) {
            log_error(1, "Cannot read encrypted file or invalid format.\n");
            return 1;
        }
        
        printf("\nStarting file decryption with AES-%d-CTR.\n", aes_key_bits);
        if (!read_input_string("Enter password used for encryption: ", password, sizeof(password),
                               SCANF_PASSWORD_FORMAT, "Cannot read password.\n")) {
            return 1;
        }
        
        // 저장할 경로 입력
        char save_path[MAX_PATH_LENGTH];
        if (!read_input_string("Enter path to save decrypted file (excluding filename): ",
                               save_path, sizeof(save_path), SCANF_PATH_FORMAT,
                               "Cannot read save path.\n")) {
            return 1;
        }
        
        // 디렉토리 존재 여부 확인
        if (!platform_directory_exists(save_path)) {
            log_error(1, "Directory does not exist: %s\n", save_path);
            return 1;
        }
        
        // 파일 이름 입력 (확장자는 자동으로 추가됨)
        char file_name[MAX_FILENAME_LENGTH];
        if (!read_input_string("Enter decrypted file name (extension will be added automatically): ",
                               file_name, sizeof(file_name), SCANF_FILENAME_FORMAT,
                               "Cannot read file name.\n")) {
            return 1;
        }
        
        // 최종 출력 경로 생성 (경로 + 파일명, 확장자는 decrypt_file에서 추가)
        char output_path[MAX_PATH_LENGTH];
        build_output_path(output_path, sizeof(output_path), save_path, file_name, NULL);
        
        char actual_output_path[MAX_PATH_LENGTH];
        if (decrypt_file(file_path, output_path, password, actual_output_path, sizeof(actual_output_path))) {
            print_operation_success("decrypt", actual_output_path);
        } else {
            log_error(1, "File decryption failed.\n");
            return 1;
        }
    }
    
    return 0;
}
#endif // BUILD_GUI