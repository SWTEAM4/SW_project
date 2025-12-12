#ifndef KDF_H
#define KDF_H

#include <stdint.h>
#include <stddef.h>
#include "crypto_api.h"

#ifdef __cplusplus
extern "C" {
#endif

// PBKDF2 관련 상수
#define PBKDF2_BLOCK_INDEX_SIZE 4        // 블록 인덱스 바이트 수 (big-endian)
#define PBKDF2_SALT_BLOCK_MAX_SIZE 256   // salt_block 최대 크기

/**
 * PBKDF2 스타일 키 도출 함수
 * 패스워드를 반복 해싱하여 키를 생성
 * 
 * @param password 사용자 패스워드
 * @param password_len 패스워드 길이
 * @param salt 솔트 (NULL이면 기본값 사용)
 * @param salt_len 솔트 길이
 * @param iterations 반복 횟수 (기본값: 10000)
 * @param output 출력 버퍼
 * @param output_len 출력 길이 (바이트)
 */
void pbkdf2_sha512(const uint8_t* password, size_t password_len,
                   const uint8_t* salt, size_t salt_len,
                   uint32_t iterations,
                   uint8_t* output, size_t output_len);

#ifdef __cplusplus
}
#endif

#endif // KDF_H

