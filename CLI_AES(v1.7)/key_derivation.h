#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 키 도출: PBKDF2-SHA512 -> AES 키 + HMAC 키
void derive_keys(const char* password, int aes_key_bits,
                 const uint8_t* salt, size_t salt_len,
                 uint8_t* aes_key, uint8_t* hmac_key);

#ifdef __cplusplus
}
#endif

#endif // KEY_DERIVATION_H

