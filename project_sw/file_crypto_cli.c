#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#ifdef _WIN32
#include <io.h>
#include <sys/stat.h>
#define access _access
#define F_OK 0
#else
#include <unistd.h>
#include <sys/stat.h>
#endif
#include "crypto_api.h"
#include "sha512.h"
#include "hmac_sha512.h"

// 파일 헤더 구조
#define FILE_SIGNATURE "AESC"
#define FILE_VERSION 0x01
#define AES_KEY_LEN_128 0x01
#define AES_KEY_LEN_192 0x02
#define AES_KEY_LEN_256 0x03
#define MODE_CTR 0x02
#define HMAC_ENABLED 0x01
#define HEADER_SIZE 32
#define NONCE_SIZE 8
#define HMAC_SIZE 64

// 헤더 구조체
typedef struct {
    char signature[4];      // [0:4] "AESC"
    uint8_t version;       // [4:5] 0x01
    uint8_t aes_key_len;    // [5:6] 0x01/0x02/0x03
    uint8_t mode;           // [6:7] 0x02 (CTR)
    uint8_t hmac_enabled;   // [7:8] 0x01
    uint8_t nonce[8];       // [8:16] Nonce
    uint8_t reserved[16];   // [16:32] Reserved
} FileHeader;

// 난수 생성 (간단한 구현)
static void generate_nonce(uint8_t* nonce, size_t len) {
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < len; i++) {
        nonce[i] = (uint8_t)(rand() & 0xFF);
    }
}

// 파일 존재 여부 확인
static int file_exists(const char* path) {
    if (!path || path[0] == '\0') {
        return 0;
    }
#ifdef _WIN32
    return (access(path, F_OK) == 0);
#else
    return (access(path, F_OK) == 0);
#endif
}

// 디렉토리인지 확인
static int is_directory(const char* path) {
    if (!path || path[0] == '\0') {
        return 0;
    }
#ifdef _WIN32
    struct _stat info;
    if (_stat(path, &info) != 0) {
        return 0;
    }
    return ((info.st_mode & _S_IFDIR) != 0);
#else
    struct stat info;
    if (stat(path, &info) != 0) {
        return 0;
    }
    return S_ISDIR(info.st_mode);
#endif
}

// 파일 크기 확인 (안전한 방법)
static long get_file_size(FILE* fp) {
    if (!fp) return -1;
    
    long current_pos = ftell(fp);
    if (current_pos < 0) return -1;
    
    if (fseek(fp, 0, SEEK_END) != 0) return -1;
    
    long size = ftell(fp);
    if (size < 0) return -1;
    
    if (fseek(fp, current_pos, SEEK_SET) != 0) return -1;
    
    return size;
}

// 안전한 파일 읽기 함수
static int read_file_safe(const char* filepath, uint8_t** buffer, size_t* size) {
    if (!filepath || !buffer || !size) {
        printf("오류: 잘못된 파라미터입니다.\n");
        return 1;
    }
    
    // 파일 경로 검증 (빈 문자열이나 공백만 있는 경우)
    if (filepath[0] == '\0') {
        printf("오류: 파일 경로가 비어있습니다.\n");
        return 1;
    }
    
    // 파일 존재 확인
    if (!file_exists(filepath)) {
        printf("오류: 파일이 존재하지 않습니다: %s\n", filepath);
        return 1;
    }
    
    // 디렉토리인지 확인
    if (is_directory(filepath)) {
        printf("오류: 입력한 경로는 디렉토리입니다. 파일 경로를 입력해주세요: %s\n", filepath);
        return 1;
    }
    
    // 파일 열기
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        // errno 21은 EISDIR (Is a directory) 오류
        if (errno == 21) {
            printf("오류: 입력한 경로는 디렉토리입니다. 파일 경로를 입력해주세요: %s\n", filepath);
        } else {
            printf("오류: 파일을 열 수 없습니다: %s (errno: %d)\n", filepath, errno);
        }
        return 1;
    }
    
    // 파일 크기 확인 (파일 포인터를 처음으로 이동)
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        printf("오류: 파일 크기 확인 중 오류 발생: %s (errno: %d)\n", filepath, errno);
        return 1;
    }
    
    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        printf("오류: 파일 크기를 확인할 수 없습니다: %s (errno: %d)\n", filepath, errno);
        return 1;
    }
    
    if (file_size == 0) {
        fclose(fp);
        printf("오류: 파일이 비어있습니다: %s\n", filepath);
        return 1;
    }
    
    // 파일 포인터를 처음으로 명시적으로 이동
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        printf("오류: 파일 포인터를 처음으로 이동할 수 없습니다: %s (errno: %d)\n", filepath, errno);
        return 1;
    }
    
    // 메모리 할당
    *size = (size_t)file_size;
    *buffer = (uint8_t*)malloc(*size);
    if (!*buffer) {
        fclose(fp);
        printf("오류: 메모리 할당 실패 (파일 크기: %zu 바이트)\n", *size);
        return 1;
    }
    
    // 파일 읽기 (전체를 한 번에 읽기)
    size_t read_bytes = fread(*buffer, 1, *size, fp);
    
    // 읽기 오류 확인
    if (ferror(fp)) {
        free(*buffer);
        *buffer = NULL;
        fclose(fp);
        printf("오류: 파일 읽기 중 오류 발생: %s (errno: %d)\n", filepath, errno);
        return 1;
    }
    
    // 읽은 바이트 수 확인
    if (read_bytes != *size) {
        free(*buffer);
        *buffer = NULL;
        fclose(fp);
        printf("오류: 파일 읽기 실패 - 파일: %s (예상: %zu 바이트, 실제 읽음: %zu 바이트)\n", 
               filepath, *size, read_bytes);
        return 1;
    }
    
    // 파일 닫기
    if (fclose(fp) != 0) {
        free(*buffer);
        *buffer = NULL;
        printf("오류: 파일 닫기 실패: %s (errno: %d)\n", filepath, errno);
        return 1;
    }
    
    return 0;
}

// 안전한 파일 쓰기 함수
static int write_file_safe(const char* filepath, const uint8_t* data, size_t size) {
    if (!filepath || !data) {
        printf("오류: 잘못된 파라미터입니다.\n");
        return 1;
    }
    
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        printf("오류: 출력 파일을 생성할 수 없습니다: %s (errno: %d)\n", filepath, errno);
        return 1;
    }
    
    size_t written = fwrite(data, 1, size, fp);
    if (written != size) {
        fclose(fp);
        printf("오류: 파일 쓰기 실패 (예상: %zu 바이트, 실제 씀: %zu 바이트)\n", size, written);
        return 1;
    }
    
    if (fclose(fp) != 0) {
        printf("오류: 파일 닫기 실패\n");
        return 1;
    }
    
    return 0;
}

// 패스워드에서 키 생성
// SHA-512 출력(64바이트)에서:
// - 앞의 n바이트를 AES 키로 사용 (16/24/32바이트)
// - 뒤의 24바이트를 HMAC 키로 사용
static void derive_keys_from_password(const char* password, int aes_key_bits,
                                      uint8_t* aes_key, uint8_t* hmac_key) {
    SHA512_CTX ctx;
    uint8_t hash[64];  // SHA-512 출력
    
    // 패스워드를 SHA-512로 해시
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)password, strlen(password));
    sha512_final(&ctx, hash);
    
    // AES 키 추출 (앞의 n바이트)
    int aes_key_len = aes_key_bits / 8;
    memcpy(aes_key, hash, aes_key_len);
    
    // HMAC 키 추출 (뒤의 24바이트 = 192비트)
    memcpy(hmac_key, hash + 40, 24);  // 64 - 24 = 40부터 시작
}

// 파일 암호화
static int encrypt_file(const char* input_path, const char* output_path,
                        const char* password, int aes_key_bits) {
    // 안전한 파일 읽기
    uint8_t* plaintext = NULL;
    size_t plaintext_size = 0;
    if (read_file_safe(input_path, &plaintext, &plaintext_size) != 0) {
        return 1;
    }
    
    // 키 생성
    uint8_t aes_key[32];
    uint8_t hmac_key[24];
    derive_keys_from_password(password, aes_key_bits, aes_key, hmac_key);
    
    // AES 컨텍스트 초기화
    AES_CTX aes_ctx;
    if (AES_set_key(&aes_ctx, aes_key, aes_key_bits) != CRYPTO_SUCCESS) {
        free(plaintext);
        printf("오류: AES 키 설정 실패\n");
        return 1;
    }
    
    // Nonce 생성
    uint8_t nonce[8];
    generate_nonce(nonce, 8);
    
    // Nonce를 16바이트로 확장 (앞 8바이트는 nonce, 뒤 8바이트는 카운터)
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, nonce, 8);
    memset(nonce_counter + 8, 0, 8);  // 카운터는 0부터 시작
    
    // 암호화
    uint8_t* ciphertext = (uint8_t*)malloc(plaintext_size);
    if (!ciphertext) {
        free(plaintext);
        printf("오류: 메모리 할당 실패\n");
        return 1;
    }
    
    uint8_t nonce_counter_copy[16];
    memcpy(nonce_counter_copy, nonce_counter, 16);
    if (AES_CTR_crypt(&aes_ctx, plaintext, plaintext_size, ciphertext, nonce_counter_copy) != CRYPTO_SUCCESS) {
        free(plaintext);
        free(ciphertext);
        printf("오류: 암호화 실패\n");
        return 1;
    }
    
    // HMAC 계산 (암호문에 대해)
    uint8_t hmac[64];
    hmac_sha512(hmac_key, 24, ciphertext, plaintext_size, hmac);
    
    // 헤더 작성
    FileHeader header;
    memcpy(header.signature, FILE_SIGNATURE, 4);
    header.version = FILE_VERSION;
    header.aes_key_len = (aes_key_bits == 128) ? AES_KEY_LEN_128 :
                         (aes_key_bits == 192) ? AES_KEY_LEN_192 : AES_KEY_LEN_256;
    header.mode = MODE_CTR;
    header.hmac_enabled = HMAC_ENABLED;
    memcpy(header.nonce, nonce, 8);
    memset(header.reserved, 0, 16);
    
    // 출력 파일 작성 (헤더 + 암호문 + HMAC)
    size_t total_size = sizeof(FileHeader) + plaintext_size + 64;
    uint8_t* output_data = (uint8_t*)malloc(total_size);
    if (!output_data) {
        free(plaintext);
        free(ciphertext);
        printf("오류: 메모리 할당 실패\n");
        return 1;
    }
    
    memcpy(output_data, &header, sizeof(FileHeader));
    memcpy(output_data + sizeof(FileHeader), ciphertext, plaintext_size);
    memcpy(output_data + sizeof(FileHeader) + plaintext_size, hmac, 64);
    
    if (write_file_safe(output_path, output_data, total_size) != 0) {
        free(plaintext);
        free(ciphertext);
        free(output_data);
        return 1;
    }
    
    free(plaintext);
    free(ciphertext);
    free(output_data);
    
    printf("파일 암호화와 HMAC 생성에 성공하였습니다.\n");
    return 0;
}

// 파일 복호화
static int decrypt_file(const char* input_path, const char* output_path,
                        const char* password) {
    // 파일 존재 확인
    if (!file_exists(input_path)) {
        printf("오류: 파일이 존재하지 않습니다: %s\n", input_path);
        return 1;
    }
    
    // 전체 파일 읽기
    uint8_t* file_data = NULL;
    size_t file_size = 0;
    if (read_file_safe(input_path, &file_data, &file_size) != 0) {
        return 1;
    }
    
    // 최소 파일 크기 확인 (헤더 + HMAC)
    if (file_size < sizeof(FileHeader) + HMAC_SIZE) {
        free(file_data);
        printf("오류: 파일이 너무 작습니다 (최소 %zu 바이트 필요)\n", sizeof(FileHeader) + HMAC_SIZE);
        return 1;
    }
    
    // 헤더 읽기
    FileHeader header;
    memcpy(&header, file_data, sizeof(FileHeader));
    
    // 시그니처 검증
    if (memcmp(header.signature, FILE_SIGNATURE, 4) != 0) {
        free(file_data);
        printf("오류: 잘못된 파일 형식입니다.\n");
        return 1;
    }
    
    // AES 키 길이 확인
    int aes_key_bits;
    if (header.aes_key_len == AES_KEY_LEN_128) aes_key_bits = 128;
    else if (header.aes_key_len == AES_KEY_LEN_192) aes_key_bits = 192;
    else if (header.aes_key_len == AES_KEY_LEN_256) aes_key_bits = 256;
    else {
        free(file_data);
        printf("오류: 지원하지 않는 AES 키 길이입니다.\n");
        return 1;
    }
    
    // 암호문과 HMAC 추출
    size_t ciphertext_size = file_size - sizeof(FileHeader) - HMAC_SIZE;
    uint8_t* ciphertext = (uint8_t*)malloc(ciphertext_size);
    if (!ciphertext) {
        free(file_data);
        printf("오류: 메모리 할당 실패\n");
        return 1;
    }
    
    memcpy(ciphertext, file_data + sizeof(FileHeader), ciphertext_size);
    
    uint8_t stored_hmac[64];
    memcpy(stored_hmac, file_data + sizeof(FileHeader) + ciphertext_size, 64);
    
    free(file_data);
    
    // 키 생성
    uint8_t aes_key[32];
    uint8_t hmac_key[24];
    derive_keys_from_password(password, aes_key_bits, aes_key, hmac_key);
    
    // HMAC 검증
    uint8_t computed_hmac[64];
    hmac_sha512(hmac_key, 24, ciphertext, ciphertext_size, computed_hmac);
    
    if (memcmp(stored_hmac, computed_hmac, 64) != 0) {
        free(ciphertext);
        printf("오류: HMAC 검증 실패. 파일이 손상되었거나 잘못된 패스워드입니다.\n");
        return 1;
    }
    
    printf("무결성이 검증되었습니다. 파일 복호화에 성공했습니다.\n");
    
    // AES 컨텍스트 초기화
    AES_CTX aes_ctx;
    if (AES_set_key(&aes_ctx, aes_key, aes_key_bits) != CRYPTO_SUCCESS) {
        free(ciphertext);
        printf("오류: AES 키 설정 실패\n");
        return 1;
    }
    
    // Nonce를 16바이트로 확장
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, header.nonce, 8);
    memset(nonce_counter + 8, 0, 8);
    
    // 복호화
    uint8_t* plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) {
        free(ciphertext);
        printf("오류: 메모리 할당 실패\n");
        return 1;
    }
    
    if (AES_CTR_crypt(&aes_ctx, ciphertext, ciphertext_size, plaintext, nonce_counter) != CRYPTO_SUCCESS) {
        free(plaintext);
        free(ciphertext);
        printf("오류: 복호화 실패\n");
        return 1;
    }
    
    // 출력 파일 작성
    if (write_file_safe(output_path, plaintext, ciphertext_size) != 0) {
        free(plaintext);
        free(ciphertext);
        return 1;
    }
    
    free(plaintext);
    free(ciphertext);
    
    return 0;
}

// 패스워드 입력 (에코 없이)
static void get_password(char* password, size_t max_len) {
    printf("패스워드를 입력하세요: ");
    fflush(stdout);
    
    // 간단한 구현 (실제로는 에코를 끄는 것이 좋지만, 여기서는 기본 입력 사용)
    if (fgets(password, (int)max_len, stdin) == NULL) {
        password[0] = '\0';
        return;
    }
    
    // 개행 문자 제거
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }
}

int main(void) {
    int choice;
    char input_path[512];
    char output_path[512];
    char password[256];
    int aes_key_bits;
    
    printf("=======================================\n");
    printf("      파일 암호화/복호화 프로그램      \n");
    printf("=======================================\n\n");
    
    while (1) {
        printf("\n메뉴를 선택하세요:\n");
        printf("1. 파일 암호화\n");
        printf("2. 파일 복호화\n");
        printf("0. 종료\n");
        printf("선택: ");
        
        if (scanf("%d", &choice) != 1) {
            printf("잘못된 입력입니다.\n");
            while (getchar() != '\n');  // 입력 버퍼 비우기
            continue;
        }
        while (getchar() != '\n');  // 입력 버퍼 비우기
        
        if (choice == 0) {
            printf("프로그램을 종료합니다.\n");
            break;
        }
        else if (choice == 1) {
            // 파일 암호화
            printf("\n암호화할 파일 경로를 입력하세요: ");
            if (fgets(input_path, sizeof(input_path), stdin) == NULL) continue;
            size_t len = strlen(input_path);
            if (len > 0 && input_path[len - 1] == '\n') {
                input_path[len - 1] = '\0';
            }
            
            printf("출력 파일 경로를 입력하세요 (예: output.enc): ");
            if (fgets(output_path, sizeof(output_path), stdin) == NULL) continue;
            len = strlen(output_path);
            if (len > 0 && output_path[len - 1] == '\n') {
                output_path[len - 1] = '\0';
            }
            
            printf("AES 키 길이를 선택하세요 (128/192/256): ");
            if (scanf("%d", &aes_key_bits) != 1) {
                printf("잘못된 입력입니다.\n");
                while (getchar() != '\n');
                continue;
            }
            while (getchar() != '\n');
            
            if (aes_key_bits != 128 && aes_key_bits != 192 && aes_key_bits != 256) {
                printf("오류: 지원하는 키 길이는 128, 192, 256입니다.\n");
                continue;
            }
            
            printf("패스워드를 입력하세요: ");
            if (fgets(password, sizeof(password), stdin) == NULL) continue;
            len = strlen(password);
            if (len > 0 && password[len - 1] == '\n') {
                password[len - 1] = '\0';
            }
            
            printf("\nAES-%d-CTR로 파일 암호화를 시작합니다.\n", aes_key_bits);
            encrypt_file(input_path, output_path, password, aes_key_bits);
        }
        else if (choice == 2) {
            // 파일 복호화
            printf("\n복호화할 파일 경로를 입력하세요: ");
            if (fgets(input_path, sizeof(input_path), stdin) == NULL) continue;
            size_t len = strlen(input_path);
            if (len > 0 && input_path[len - 1] == '\n') {
                input_path[len - 1] = '\0';
            }
            
            // 헤더에서 AES 키 길이 확인
            if (!file_exists(input_path)) {
                printf("오류: 파일이 존재하지 않습니다: %s\n", input_path);
                continue;
            }
            
            FILE* f = fopen(input_path, "rb");
            if (!f) {
                printf("오류: 파일을 열 수 없습니다: %s (errno: %d)\n", input_path, errno);
                continue;
            }
            
            FileHeader header;
            if (fread(&header, 1, sizeof(FileHeader), f) != sizeof(FileHeader)) {
                fclose(f);
                printf("오류: 파일 헤더 읽기 실패\n");
                continue;
            }
            fclose(f);
            
            int aes_key_bits_dec;
            if (header.aes_key_len == AES_KEY_LEN_128) aes_key_bits_dec = 128;
            else if (header.aes_key_len == AES_KEY_LEN_192) aes_key_bits_dec = 192;
            else if (header.aes_key_len == AES_KEY_LEN_256) aes_key_bits_dec = 256;
            else {
                printf("오류: 지원하지 않는 AES 키 길이입니다.\n");
                continue;
            }
            
            printf("출력 파일 경로를 입력하세요: ");
            if (fgets(output_path, sizeof(output_path), stdin) == NULL) continue;
            len = strlen(output_path);
            if (len > 0 && output_path[len - 1] == '\n') {
                output_path[len - 1] = '\0';
            }
            
            printf("암호화 시 사용했던 패스워드를 입력하세요: ");
            if (fgets(password, sizeof(password), stdin) == NULL) continue;
            len = strlen(password);
            if (len > 0 && password[len - 1] == '\n') {
                password[len - 1] = '\0';
            }
            
            printf("\nAES-%d-CTR로 파일 복호화를 시작합니다.\n", aes_key_bits_dec);
            decrypt_file(input_path, output_path, password);
        }
        else {
            printf("잘못된 선택입니다.\n");
        }
    }
    
    return 0;
}

