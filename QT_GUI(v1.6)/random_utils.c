#include "random_utils.h"
#include "crypto_api.h"
#include <stdio.h>
#include <stdlib.h>

static int fill_random_bytes(uint8_t* buffer, size_t len, const char* purpose) {
    if (crypto_random_bytes(buffer, len) == CRYPTO_SUCCESS) {
#ifndef NDEBUG
        printf("[DEBUG] OpenSSL RAND_bytes random number generation succeeded (%s)\n", purpose);
#endif
        return 1;
    }
    
    // OpenSSL이 없는 경우 fallback (보안상 권장하지 않음)
#ifndef NDEBUG
    printf("[DEBUG] OpenSSL RAND_bytes failed for %s, using fallback rand()\n", purpose);
#endif
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0; // fallback 사용됨을 표시
}

// 랜덤 nonce 생성 (OpenSSL RAND_bytes 사용)
int generate_nonce(uint8_t* nonce, size_t len) {
    return fill_random_bytes(nonce, len, "nonce");
}

// 랜덤 salt 생성 (OpenSSL RAND_bytes 사용)
int generate_salt(uint8_t* salt, size_t len) {
    return fill_random_bytes(salt, len, "salt");
}

