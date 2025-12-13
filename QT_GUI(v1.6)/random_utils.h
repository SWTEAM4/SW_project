#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 랜덤 nonce 생성
int generate_nonce(uint8_t* nonce, size_t len);

// 랜덤 salt 생성
int generate_salt(uint8_t* salt, size_t len);

#ifdef __cplusplus
}
#endif

#endif // RANDOM_UTILS_H

