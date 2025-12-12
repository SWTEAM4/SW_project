#include "kdf.h"
#include "sha512.h"
#include "hmac_sha512.h"
#include <string.h>

/**
 * PBKDF2-SHA512 구현
 * RFC 2898 기반
 */
void pbkdf2_sha512(const uint8_t* password, size_t password_len,
                   const uint8_t* salt, size_t salt_len,
                   uint32_t iterations,
                   uint8_t* output, size_t output_len)
{
    if (!password || !output || password_len == 0 || output_len == 0) {
        return;
    }

    // 기본 솔트 (salt가 NULL이거나 길이가 0인 경우)
    uint8_t default_salt[] = { 0x41, 0x45, 0x53, 0x43 }; // "AESC"
    const uint8_t* actual_salt = salt;
    size_t actual_salt_len = salt_len;
    
    if (!salt || salt_len == 0) {
        actual_salt = default_salt;
        actual_salt_len = sizeof(default_salt);
    }

    // 필요한 블록 수 계산 (SHA512는 64바이트 출력)
    size_t blocks_needed = (output_len + (SHA512_DIGEST_LENGTH - 1)) / SHA512_DIGEST_LENGTH;
    
    for (size_t block = 0; block < blocks_needed; block++) {
        // U1 = HMAC-SHA512(password, salt || block_index)
        uint8_t salt_block[PBKDF2_SALT_BLOCK_MAX_SIZE]; // 충분한 크기
        size_t salt_block_len = actual_salt_len + PBKDF2_BLOCK_INDEX_SIZE;
        
        memcpy(salt_block, actual_salt, actual_salt_len);
        // Big-endian으로 블록 인덱스 추가
        salt_block[actual_salt_len] = (uint8_t)((block + 1) >> 24);
        salt_block[actual_salt_len + 1] = (uint8_t)((block + 1) >> 16);
        salt_block[actual_salt_len + 2] = (uint8_t)((block + 1) >> 8);
        salt_block[actual_salt_len + 3] = (uint8_t)(block + 1);
        
        // HMAC-SHA512 계산
        uint8_t u[SHA512_DIGEST_LENGTH];
        hmac_sha512(password, password_len, salt_block, salt_block_len, u);
        
        uint8_t t[SHA512_DIGEST_LENGTH];
        memcpy(t, u, SHA512_DIGEST_LENGTH);
        
        // U2, U3, ... U_iterations 계산 및 XOR
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha512(password, password_len, u, SHA512_DIGEST_LENGTH, u);
            for (size_t j = 0; j < SHA512_DIGEST_LENGTH; j++) {
                t[j] ^= u[j];
            }
        }
        
        // 출력에 복사 (필요한 만큼만)
        size_t copy_len = (output_len - block * SHA512_DIGEST_LENGTH < SHA512_DIGEST_LENGTH) ? 
                          (output_len - block * SHA512_DIGEST_LENGTH) : SHA512_DIGEST_LENGTH;
        memcpy(output + block * SHA512_DIGEST_LENGTH, t, copy_len);
    }
}

