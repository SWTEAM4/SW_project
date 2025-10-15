#ifndef __CRYPTO_API_H__
#define __CRYPTO_API_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* --------------------------- Constants --------------------------- */
#define AES_BLOCK_SIZE                    16
#define AES_KEY_LENGTH_128                16     // bytes
#define AES_KEY_LENGTH_192                24
#define AES_KEY_LENGTH_256                32
#define AES_ROUND_128                     10
#define AES_ROUND_192                     12
#define AES_ROUND_256                     14

#define SHA256_BLOCK_SIZE       64   // 512-bit block (SHA256이 입력을 64바이트 단위로 처리)
#define SHA256_DIGEST_LENGTH    32   // 256-bit digest (SHA256의 최종 해시 출력 길이)

/* --------------------------- Error codes --------------------------- */
typedef enum { // enum : 열거형(정수 상수들의 집합에 이름을 붙여 쓰기 좋게 만든 타입)
    CRYPTO_SUCCESS = 0,          // 성공

    CRYPTO_ERR_NULL_CONTEXT,     // 내부 필수 포인터가 NULL
    CRYPTO_ERR_NOT_INITIALIZED,  // init/set_key 등 선행 초기화 없이 사용할 경우
    CRYPTO_ERR_INVALID_INPUT,    // 포인터/길이 조합이 잘못됨(ex. data=NULL && len>0)
    CRYPTO_ERR_BUFFER_TOO_SMALL, // 출력/작업 버퍼가 요구 크기보다 작음
    CRYPTO_ERR_INTERNAL_FAILURE, // 내부 오류(시스템 콜 실패, 예기치 못한 상태 등)
    CRYPTO_ERR_INVALID_ARGUMENT  // 파라미터 범위/값 오류(키 길이, nonce 길이 등)
} CRYPTO_STATUS; // 타입 이름

/* --------------------------- AES context --------------------------- */
// AES 연산에 필요한 state를 담아 두는 구조체
typedef struct {
    uint8_t round_keys[240];  // 라운드키 저장 공간 (AES256의 최대 240바이트에 맞춰 배열 선언)
    uint8_t Nr;               // 라운드 수 
    uint8_t Nk;               // 키 워드 수 (4/6/8) (워드 = 4바이트)
    uint16_t key_bits;        // 키 길이 (128/192/256)
} AES_CTX;

/* --------------------------- AES 기본 API --------------------------- */
CRYPTO_STATUS AES_set_key(AES_CTX* ctx, const uint8_t* key, int key_bits); // AES 키 생성 (MK와 키 길이를 받아 내부에서 라운드키를 생성하는 함수))
CRYPTO_STATUS AES_encrypt_block(const AES_CTX* ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]); // AES 암호화
CRYPTO_STATUS AES_decrypt_block(const AES_CTX* ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]); // AES 복호화

/* --------------------------- Modes (CTR) --------------------------- */
// 호출 후 nonce_counter가 증가됨
// 함수 하나로 암복호화 양방향 처리
// length==0일 경우 성공 반환
CRYPTO_STATUS AES_CTR_crypt(const AES_CTX* ctx, const uint8_t* in, size_t length, uint8_t* out, uint8_t nonce_counter[AES_BLOCK_SIZE]);

/* --------------------------- SHA-256 context --------------------------- */
typedef struct {
    uint32_t state[8];                 // 내부 해시 상태
    uint64_t bitlen;                   // 처리한 비트 길이 누적
    uint8_t  data[SHA256_BLOCK_SIZE];  // 나머지 블록 버퍼
    size_t   datalen;                  // 버퍼에 현재 쌓인 바이트 수 (0~63 바이트)
} SHA256_CTX;

/* --------------------------- SHA-256 기본 API --------------------------- */
CRYPTO_STATUS SHA256_init(SHA256_CTX *ctx); // 초기화: state를 초기 IV로 세팅하고 나머지 초기화

// len==0일 경우 성공 반환
CRYPTO_STATUS SHA256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len); // 입력을 받아 64바이트 블록 단위로 압축 (여러 번 호출 가능)
CRYPTO_STATUS SHA256_final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_LENGTH]); // 패딩 + 마지막 압축 후, 최종 32바이트 해시를 digest에 저장

#ifdef __cplusplus
}
#endif /*extern "C"*/

#endif /*__CRYPTO_API_H__*/
