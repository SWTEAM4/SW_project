#ifndef FILE_CRYPTO_H
#define FILE_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// .enc 파일 헤더 구조
#define ENC_SIGNATURE "AESC"
#define ENC_VERSION 0x01
#define ENC_MODE_CTR 0x02
#define ENC_HMAC_ENABLED 0x01
#define ENC_HEADER_SIZE 40
#define ENC_NONCE_SIZE 8
#define ENC_HMAC_SIZE 64

// 헤더 구조
typedef struct {
    uint8_t signature[4];      // [0:4] "AESC"
    uint8_t version;           // [4:5] 0x01
    uint8_t key_length_code;   // [5:6] 0x01=128, 0x02=192, 0x03=256
    uint8_t mode_code;         // [6:7] 0x02=CTR
    uint8_t hmac_enabled;      // [7:8] 0x01=enabled
    uint8_t nonce[8];          // [8:16] Nonce
    uint8_t format[8];         // [16:24] Original file extension/signature (e.g., ".hwp", ".png", ".jpeg", ".txt")
    uint8_t reserved[16];      // [24:40] Reserved
} EncFileHeader;

// 진행률 콜백 함수 타입
typedef void (*progress_callback_t)(long processed, long total, void* user_data);

// 패스워드 검증 (영문+숫자, 대소문자, 최대 10자)
int validate_password(const char* password);

// 파일 암호화
int encrypt_file(const char* input_path, const char* output_path,
                 int aes_key_bits, const char* password);

// 파일 암호화 (진행률 콜백 지원)
int encrypt_file_with_progress(const char* input_path, const char* output_path,
                               int aes_key_bits, const char* password,
                               progress_callback_t progress_cb, void* user_data);

// 파일 복호화
int decrypt_file(const char* input_path, const char* output_path,
                 const char* password, char* final_output_path, size_t final_path_size);

// 파일 복호화 (진행률 콜백 지원)
int decrypt_file_with_progress(const char* input_path, const char* output_path,
                               const char* password, char* final_output_path, size_t final_path_size,
                               progress_callback_t progress_cb, void* user_data);

// 헤더에서 AES 키 길이 읽기
int read_aes_key_length(const char* input_path);

#ifdef __cplusplus
}
#endif

#endif // FILE_CRYPTO_H


