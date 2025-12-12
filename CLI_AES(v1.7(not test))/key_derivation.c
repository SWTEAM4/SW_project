#include "key_derivation.h"
#include "kdf.h"
#include <string.h>

// PBKDF2 반복 횟수
#define PBKDF2_ITERATIONS 10000
// KDF 출력 크기 (SHA512는 64바이트)
#define KDF_OUTPUT_SIZE 64
// HMAC 키 크기
#define HMAC_KEY_SIZE 24
// KDF 출력에서 HMAC 키 시작 오프셋
#define KDF_AES_KEY_OFFSET 32

// 키 도출: PBKDF2-SHA512 -> AES 키 + HMAC 키
void derive_keys(const char* password, int aes_key_bits,
                 const uint8_t* salt, size_t salt_len,
                 uint8_t* aes_key, uint8_t* hmac_key) {
    // 1. 패스워드를 PBKDF2-SHA512로 512비트(64바이트)로 변환
    uint8_t kdf_output[KDF_OUTPUT_SIZE];
    pbkdf2_sha512((const uint8_t*)password, strlen(password),
                  salt, salt_len, PBKDF2_ITERATIONS, kdf_output, KDF_OUTPUT_SIZE);
    
    // 2. 상위 절반(32바이트)에서 AES 키 길이만큼 사용
    int aes_key_bytes = aes_key_bits / 8;
    memcpy(aes_key, kdf_output, aes_key_bytes);
    
    // 3. 하위 32바이트 중 처음 24바이트를 HMAC 키로 사용
    memcpy(hmac_key, kdf_output + KDF_AES_KEY_OFFSET, HMAC_KEY_SIZE);
}

