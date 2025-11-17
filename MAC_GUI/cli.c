#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "crypto_api.h"
#include "aes.h"
#include "sha512.h"
#include "hmac_sha512.h"
#include "kdf.h"
#include "file_crypto.h"
#include "platform_utils.h"

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
#endif

// 패스워드 검증 (영문+숫자, 대소문자, 최대 10자)
int validate_password(const char* password) {
    if (!password) return 0;
    size_t len = strlen(password);
    if (len == 0 || len > 10) return 0;
    
    for (size_t i = 0; i < len; i++) {
        char c = password[i];
        if (!((c >= 'A' && c <= 'Z') || 
              (c >= 'a' && c <= 'z') || 
              (c >= '0' && c <= '9'))) {
            return 0;
        }
    }
    return 1;
}

// 키 도출: KDF -> SHA512 -> AES 키 + HMAC 키
void derive_keys(const char* password, int aes_key_bits, 
                 uint8_t* aes_key, uint8_t* hmac_key) {
    // 1. 패스워드를 KDF를 통해서 SHA512 입력으로 변환
    uint8_t kdf_output[64];
    pbkdf2_sha512((const uint8_t*)password, strlen(password),
                  NULL, 0, 10000, kdf_output, 64);
    
    // 2. KDF 출력을 SHA512 입력으로 사용하여 해싱
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, kdf_output, 64);
    uint8_t sha512_output[64];
    sha512_final(&ctx, sha512_output);
    
    // 3. SHA512 출력에서 앞의 n바이트를 AES 키로
    int aes_key_bytes = aes_key_bits / 8;
    memcpy(aes_key, sha512_output, aes_key_bytes);
    
    // 4. SHA512 출력에서 뒤의 192비트(24바이트)를 HMAC 키로
    memcpy(hmac_key, sha512_output + (64 - 24), 24);
}

// 랜덤 nonce 생성 (OpenSSL RAND_bytes 사용)
int generate_nonce(uint8_t* nonce, size_t len) {
    if (crypto_random_bytes(nonce, len) == CRYPTO_SUCCESS) {
        return 1;
    }
    // OpenSSL이 없는 경우 fallback (보안상 권장하지 않음)
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < len; i++) {
        nonce[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0; // fallback 사용됨을 표시
}

// 파일 경로에서 확장자 추출 (예: "file.txt" -> ".txt")
// 확장자가 없으면 빈 문자열 반환
void extract_extension(const char* file_path, char* ext, size_t ext_size) {
    if (!file_path || !ext || ext_size == 0) {
        if (ext && ext_size > 0) ext[0] = '\0';
        return;
    }
    
    const char* last_dot = strrchr(file_path, '.');
    const char* last_slash = strrchr(file_path, '/');
#ifdef _WIN32
    const char* last_backslash = strrchr(file_path, '\\');
    if (last_backslash && (!last_slash || last_backslash > last_slash)) {
        last_slash = last_backslash;
    }
#endif
    
    if (last_dot && (!last_slash || last_dot > last_slash)) {
        size_t ext_len = strlen(last_dot);
        if (ext_len < ext_size) {
            strncpy(ext, last_dot, ext_size - 1);
            ext[ext_size - 1] = '\0';
        } else {
            ext[0] = '\0';
        }
    } else {
        ext[0] = '\0';
    }
}

// 파일 암호화
int encrypt_file(const char* input_path, const char* output_path,
                 int aes_key_bits, const char* password) {
    FILE* fin = platform_fopen(input_path, "rb");
    if (!fin) {
        printf("오류: 파일을 열 수 없습니다: %s\n", input_path);
        return 0;
    }
    
    // 파일 크기 확인
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    if (file_size < 0) {
        fclose(fin);
        return 0;
    }
    
    // 평문 읽기
    uint8_t* plaintext = (uint8_t*)malloc(file_size);
    if (!plaintext) {
        fclose(fin);
        return 0;
    }
    fread(plaintext, 1, file_size, fin);
    fclose(fin);
    
    // 키 도출
    uint8_t aes_key[32];
    uint8_t hmac_key[24];
    derive_keys(password, aes_key_bits, aes_key, hmac_key);
    
    // AES 컨텍스트 설정
    AES_CTX aes_ctx;
    if (AES_set_key(&aes_ctx, aes_key, aes_key_bits) != CRYPTO_SUCCESS) {
        free(plaintext);
        return 0;
    }
    
    // Nonce 생성
    uint8_t nonce[8];
    generate_nonce(nonce, 8);
    
    // CTR 모드용 nonce_counter (8바이트 nonce + 8바이트 카운터)
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, nonce, 8);
    memset(nonce_counter + 8, 0, 8);
    
    // 암호화
    uint8_t* ciphertext = (uint8_t*)malloc(file_size);
    if (!ciphertext) {
        free(plaintext);
        return 0;
    }
    
    if (AES_CTR_crypt(&aes_ctx, plaintext, file_size, ciphertext, nonce_counter) != CRYPTO_SUCCESS) {
        free(plaintext);
        free(ciphertext);
        return 0;
    }
    
    // HMAC 계산 (헤더 + nonce + ciphertext에 대해)
    uint8_t hmac[64];
    HMAC_SHA512_CTX hmac_ctx;
    hmac_sha512_init(&hmac_ctx, hmac_key, 24);
    
    // 헤더 정보를 HMAC에 포함 (실제로는 nonce와 ciphertext만 포함)
    hmac_sha512_update(&hmac_ctx, nonce, 8);
    hmac_sha512_update(&hmac_ctx, ciphertext, file_size);
    hmac_sha512_final(&hmac_ctx, hmac);
    
    // 원본 파일 확장자 추출 및 헤더에 저장
    char original_ext[16];
    extract_extension(input_path, original_ext, sizeof(original_ext));
    size_t ext_len = strlen(original_ext);
    if (ext_len > 15) ext_len = 15; // 최대 15바이트
    
    // 헤더 작성
    EncFileHeader header;
    memcpy(header.signature, ENC_SIGNATURE, 4);
    header.version = ENC_VERSION;
    header.key_length_code = (aes_key_bits == 128) ? 0x01 : 
                             (aes_key_bits == 192) ? 0x02 : 0x03;
    header.mode_code = ENC_MODE_CTR;
    header.hmac_enabled = ENC_HMAC_ENABLED;
    memcpy(header.nonce, nonce, 8);
    memset(header.reserved, 0, 16);
    // reserved[0]: 확장자 길이, reserved[1~15]: 확장자 문자열
    header.reserved[0] = (uint8_t)ext_len;
    if (ext_len > 0) {
        memcpy(header.reserved + 1, original_ext, ext_len);
    }
    
    // 출력 파일 작성
    FILE* fout = platform_fopen(output_path, "wb");
    if (!fout) {
        free(plaintext);
        free(ciphertext);
        return 0;
    }
    
    fwrite(&header, 1, sizeof(header), fout);
    fwrite(ciphertext, 1, file_size, fout);
    fwrite(hmac, 1, 64, fout);
    fclose(fout);
    
    free(plaintext);
    free(ciphertext);
    
    return 1;
}

// 헤더에서 AES 키 길이 읽기 (복호화 전 확인용)
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
    if (header.key_length_code == 0x01) return 128;
    else if (header.key_length_code == 0x02) return 192;
    else if (header.key_length_code == 0x03) return 256;
    else return 0;
}

// 파일 복호화
// 실제 저장된 파일 경로를 final_output_path에 저장
int decrypt_file(const char* input_path, const char* output_path,
                 const char* password, char* final_output_path, size_t final_path_size) {
    FILE* fin = platform_fopen(input_path, "rb");
    if (!fin) {
        printf("오류: 파일을 열 수 없습니다: %s\n", input_path);
        return 0;
    }
    
    // 헤더 읽기
    EncFileHeader header;
    if (fread(&header, 1, sizeof(header), fin) != sizeof(header)) {
        fclose(fin);
        printf("오류: 파일 헤더를 읽을 수 없습니다.\n");
        return 0;
    }
    
    // 시그니처 검증
    if (memcmp(header.signature, ENC_SIGNATURE, 4) != 0) {
        fclose(fin);
        printf("오류: 잘못된 파일 형식입니다.\n");
        return 0;
    }
    
    // 파일 크기 확인
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, sizeof(header), SEEK_SET);
    
    long ciphertext_size = file_size - sizeof(header) - 64; // 헤더와 HMAC 제외
    
    if (ciphertext_size <= 0) {
        fclose(fin);
        printf("오류: 잘못된 파일 크기입니다.\n");
        return 0;
    }
    
    // 암호문 읽기
    uint8_t* ciphertext = (uint8_t*)malloc(ciphertext_size);
    if (!ciphertext) {
        fclose(fin);
        return 0;
    }
    fread(ciphertext, 1, ciphertext_size, fin);
    
    // HMAC 읽기
    uint8_t stored_hmac[64];
    fread(stored_hmac, 1, 64, fin);
    fclose(fin);
    
    // AES 키 길이 결정
    int aes_key_bits;
    if (header.key_length_code == 0x01) aes_key_bits = 128;
    else if (header.key_length_code == 0x02) aes_key_bits = 192;
    else if (header.key_length_code == 0x03) aes_key_bits = 256;
    else {
        free(ciphertext);
        printf("오류: 지원하지 않는 AES 키 길이입니다.\n");
        return 0;
    }
    
    // 키 도출
    uint8_t aes_key[32];
    uint8_t hmac_key[24];
    derive_keys(password, aes_key_bits, aes_key, hmac_key);
    
    // HMAC 검증
    uint8_t computed_hmac[64];
    HMAC_SHA512_CTX hmac_ctx;
    hmac_sha512_init(&hmac_ctx, hmac_key, 24);
    hmac_sha512_update(&hmac_ctx, header.nonce, 8);
    hmac_sha512_update(&hmac_ctx, ciphertext, ciphertext_size);
    hmac_sha512_final(&hmac_ctx, computed_hmac);
    
    if (memcmp(stored_hmac, computed_hmac, 64) != 0) {
        free(ciphertext);
        printf("오류: HMAC 무결성 검증 실패. 파일이 손상되었거나 패스워드가 잘못되었습니다.\n");
        return 0;
    }
    
    // AES 컨텍스트 설정
    AES_CTX aes_ctx;
    if (AES_set_key(&aes_ctx, aes_key, aes_key_bits) != CRYPTO_SUCCESS) {
        free(ciphertext);
        return 0;
    }
    
    // CTR 모드용 nonce_counter
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, header.nonce, 8);
    memset(nonce_counter + 8, 0, 8);
    
    // 복호화
    uint8_t* plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) {
        free(ciphertext);
        return 0;
    }
    
    if (AES_CTR_crypt(&aes_ctx, ciphertext, ciphertext_size, plaintext, nonce_counter) != CRYPTO_SUCCESS) {
        free(plaintext);
        free(ciphertext);
        return 0;
    }
    
    // 헤더에서 원본 확장자 읽기
    uint8_t ext_len = header.reserved[0];
    if (ext_len > 15) ext_len = 15;
    
    // 출력 파일 경로에 확장자 추가
    char actual_output_path[512];
    strncpy(actual_output_path, output_path, sizeof(actual_output_path) - 1);
    actual_output_path[sizeof(actual_output_path) - 1] = '\0';
    
    if (ext_len > 0) {
        // 출력 경로에 확장자가 없으면 추가
        char* last_dot = strrchr(actual_output_path, '.');
        char* last_slash = strrchr(actual_output_path, '/');
#ifdef _WIN32
        char* last_backslash = strrchr(actual_output_path, '\\');
        if (last_backslash && (!last_slash || last_backslash > last_slash)) {
            last_slash = last_backslash;
        }
#endif
        if (!last_dot || (last_slash && last_dot < last_slash)) {
            // 확장자가 없으면 추가
            size_t path_len = strlen(actual_output_path);
            if (path_len + ext_len < sizeof(actual_output_path)) {
                memcpy(actual_output_path + path_len, header.reserved + 1, ext_len);
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
        free(plaintext);
        free(ciphertext);
        return 0;
    }
    
    fwrite(plaintext, 1, ciphertext_size, fout);
    fclose(fout);
    
    free(plaintext);
    free(ciphertext);
    
    return 1;
}

#ifndef BUILD_GUI
int main(void) {
    int service;
    char file_path[512];
    char password[32];
    int aes_choice;
    int aes_key_bits;
    
    printf("=======================================\n");
    printf("       파일 암호화/복호화 프로그램      \n");
    printf("=======================================\n\n");
    
    // 서비스 선택
    printf("이용하실 서비스 번호를 입력하세요:\n");
    printf("1. 파일 암호화\n");
    printf("2. 파일 복호화\n");
    printf("선택: ");
    
    if (scanf("%d", &service) != 1 || (service != 1 && service != 2)) {
        printf("오류: 잘못된 입력입니다.\n");
        return 1;
    }
    
    if (service == 1) {
        // 암호화
        printf("\n암호화할 파일 경로를 입력하세요: ");
        if (scanf("%511s", file_path) != 1) {
            printf("오류: 파일 경로를 읽을 수 없습니다.\n");
            return 1;
        }
        
        printf("\n파일을 암호화할 AES를 입력하세요:\n");
        printf("1. AES-128\n");
        printf("2. AES-192\n");
        printf("3. AES-256\n");
        printf("선택: ");
        
        if (scanf("%d", &aes_choice) != 1 || aes_choice < 1 || aes_choice > 3) {
            printf("오류: 잘못된 선택입니다.\n");
            return 1;
        }
        
        aes_key_bits = (aes_choice == 1) ? 128 : (aes_choice == 2) ? 192 : 256;
        printf("\nAES-%d-CTR로 파일 암호화를 시작합니다.\n", aes_key_bits);
        
        printf("패스워드를 입력하세요 (영문+숫자 (대소문자) 최대 10자): ");
        if (scanf("%31s", password) != 1) {
            printf("오류: 패스워드를 읽을 수 없습니다.\n");
            return 1;
        }
        
        if (!validate_password(password)) {
            printf("오류: 패스워드는 영문+숫자 (대소문자) 최대 10자여야 합니다.\n");
            return 1;
        }
        
        // 저장할 경로 입력
        char save_path[512];
        printf("암호화된 파일을 저장할 경로를 입력하세요: ");
        if (scanf("%511s", save_path) != 1) {
            printf("오류: 저장 경로를 읽을 수 없습니다.\n");
            return 1;
        }
        
        // 파일 이름 입력
        char file_name[256];
        printf("암호화된 파일 이름을 입력하세요 (확장자 .enc는 자동 추가): ");
        if (scanf("%255s", file_name) != 1) {
            printf("오류: 파일 이름을 읽을 수 없습니다.\n");
            return 1;
        }
        
        // 최종 출력 경로 생성 (경로 + 파일명 + .enc)
        char output_path[512];
        size_t path_len = strlen(save_path);
        // 경로 끝에 구분자가 없으면 추가
        if (path_len > 0 && save_path[path_len - 1] != '/' && save_path[path_len - 1] != '\\') {
#ifdef _WIN32
            snprintf(output_path, sizeof(output_path), "%s\\%s.enc", save_path, file_name);
#else
            snprintf(output_path, sizeof(output_path), "%s/%s.enc", save_path, file_name);
#endif
        } else {
            snprintf(output_path, sizeof(output_path), "%s%s.enc", save_path, file_name);
        }
        
        if (encrypt_file(file_path, output_path, aes_key_bits, password)) {
            printf("파일 암호화와 hmac 생성에 성공하였습니다.\n");
            printf("암호화된 파일: %s\n", output_path);
        } else {
            printf("오류: 파일 암호화에 실패했습니다.\n");
            return 1;
        }
        
    } else if (service == 2) {
        // 복호화
        printf("\n복호화할 파일 경로를 입력하세요: ");
        if (scanf("%511s", file_path) != 1) {
            printf("오류: 파일 경로를 읽을 수 없습니다.\n");
            return 1;
        }
        
        // 헤더에서 AES 키 길이 읽기
        int aes_key_bits = read_aes_key_length(file_path);
        if (aes_key_bits == 0) {
            printf("오류: 암호화된 파일을 읽을 수 없거나 잘못된 형식입니다.\n");
            return 1;
        }
        
        printf("\nAES-%d-CTR로 파일 복호화를 시작합니다.\n", aes_key_bits);
        printf("암호화 시 사용했던 패스워드를 입력하세요: ");
        if (scanf("%31s", password) != 1) {
            printf("오류: 패스워드를 읽을 수 없습니다.\n");
            return 1;
        }
        
        // 저장할 경로 입력
        char save_path[512];
        printf("복호화된 파일을 저장할 경로를 입력하세요 (저장할 파일명 제외): ");
        if (scanf("%511s", save_path) != 1) {
            printf("오류: 저장 경로를 읽을 수 없습니다.\n");
            return 1;
        }
        
        // 파일 이름 입력 (확장자는 자동으로 추가됨)
        char file_name[256];
        printf("복호화된 파일 이름을 입력하세요 (확장자는 자동 추가): ");
        if (scanf("%255s", file_name) != 1) {
            printf("오류: 파일 이름을 읽을 수 없습니다.\n");
            return 1;
        }
        
        // 최종 출력 경로 생성 (경로 + 파일명, 확장자는 decrypt_file에서 추가)
        char output_path[512];
        size_t path_len = strlen(save_path);
        // 경로 끝에 구분자가 없으면 추가
        if (path_len > 0 && save_path[path_len - 1] != '/' && save_path[path_len - 1] != '\\') {
#ifdef _WIN32
            snprintf(output_path, sizeof(output_path), "%s\\%s", save_path, file_name);
#else
            snprintf(output_path, sizeof(output_path), "%s/%s", save_path, file_name);
#endif
        } else {
            snprintf(output_path, sizeof(output_path), "%s%s", save_path, file_name);
        }
        
        char actual_output_path[512];
        if (decrypt_file(file_path, output_path, password, actual_output_path, sizeof(actual_output_path))) {
            printf("무결성이 검증되었습니다. 파일 복호화에 성공했습니다.\n");
            printf("복호화된 파일: %s\n", actual_output_path);
        } else {
            printf("오류: 파일 복호화에 실패했습니다.\n");
            return 1;
        }
    }
    
    return 0;
}
#endif // BUILD_GUI

