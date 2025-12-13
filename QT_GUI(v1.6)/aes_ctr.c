#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "platform_utils.h"  // PLATFORM_MAC 정의를 위해 먼저 include

#ifdef USE_OPENSSL
#include <openssl/rand.h>
#endif

// macOS에서 OpenSSL 동적 로딩을 위한 추가
#ifdef PLATFORM_MAC
#include <dlfcn.h>
#include <stdlib.h>
#endif

#include "crypto_api.h"

/*****************************************************
 * AES (Advanced Encryption Standard) 내부 헬퍼 함수들
 * 이 함수들은 AES 암호화의 핵심 구성 요소입니다.
 *****************************************************/

/**
 * @brief xtimes: GF(2^8) 상에서의 곱셈 연산. T-tables 생성에 사용됩니다.
 * * AES는 '갈루아 필드(Galois Field)'라는 특수한 수학적 공간에서 연산을 수행합니다.
 * 이 함수는 입력 바이트에 2를 곱하는 연산을 GF(2^8) 규칙에 따라 수행합니다.
 * 일반적인 곱셈과 달리, 최상위 비트(MSB)가 1이면 XOR 연산(0x1b)이 추가로 발생합니다.
 * 이는 곱셈 결과가 1바이트(8비트)를 넘어가지 않도록 보장하기 위함입니다.
 */
#define xtimes(input) (((input) << 1) ^ (((input) >> 7) * 0x1b))

/**
 * @brief s_box: SubBytes 연산에 사용되는 치환 테이블.
 * * S-Box는 AES의 비선형성을 제공하는 핵심 요소입니다. 입력 바이트를 미리 정해진 다른 바이트로
 * 완전히 대체하여, 암호문이 원래 평문과 통계적 관계를 갖기 어렵게 만듭니다. (혼돈 효과)
 * 이 테이블 값은 특정 수학적 계산(역원 계산 + 아핀 변환)을 통해 설계되었습니다.
 */
static const uint8_t s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/**
 * @brief inv_s_box: Inverse SubBytes 연산에 사용되는 역 치환 테이블.
 * * 복호화 시 S-Box의 역함수로 사용됩니다.
 */
static const uint8_t inv_s_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/**
 * @brief Rcon: 라운드 상수(Round Constant). 키 스케줄링에서 사용됩니다.
 *
 * 키 스케줄링 과정에서 각 라운드 키가 이전 라운드 키와 달라지도록 보장하는 역할(라운드 대칭성 파괴)을 합니다.
 * 매 라운드마다 이 값을 XOR하여 라운드 간의 독립성을 높입니다.
 */
static const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/**
 * @brief T-tables: SubBytes와 MixColumns를 결합한 최적화 테이블 (암호화용)
 * * 각 테이블은 256개의 32비트 값을 포함하며, SubBytes와 MixColumns를 한 번에 수행합니다.
 * * T0, T1, T2, T3는 MixColumns 행렬의 각 열에 대응됩니다.
 * * 각 32비트 값은 [b0, b1, b2, b3] 4바이트를 하나의 uint32_t로 패킹한 것입니다.
 */
static uint32_t T0[256], T1[256], T2[256], T3[256];
static int tables_initialized = 0;

/**
 * @brief Inverse T-tables: Inverse SubBytes와 Inverse MixColumns를 결합한 최적화 테이블 (복호화용)
 * * 복호화 시 사용되는 T-tables입니다.
 */
static uint32_t IT0[256], IT1[256], IT2[256], IT3[256];
static int inv_tables_initialized = 0;

// T-tables 초기화 함수 (암호화용)
static void init_tables(void) {
    if (tables_initialized) return;
    
    for (int i = 0; i < 256; i++) {
        uint8_t s = s_box[i];
        uint8_t s2 = xtimes(s);      // 2·S[a]
        uint8_t s3 = s2 ^ s;         // 3·S[a]
        
        // T0[a] = [2·S[a], 1·S[a], 1·S[a], 3·S[a]]
        T0[i] = ((uint32_t)s2) | ((uint32_t)s << 8) | ((uint32_t)s << 16) | ((uint32_t)s3 << 24);
        
        // T1[a] = [3·S[a], 2·S[a], 1·S[a], 1·S[a]]
        T1[i] = ((uint32_t)s3) | ((uint32_t)s2 << 8) | ((uint32_t)s << 16) | ((uint32_t)s << 24);
        
        // T2[a] = [1·S[a], 3·S[a], 2·S[a], 1·S[a]]
        T2[i] = ((uint32_t)s) | ((uint32_t)s3 << 8) | ((uint32_t)s2 << 16) | ((uint32_t)s << 24);
        
        // T3[a] = [1·S[a], 1·S[a], 3·S[a], 2·S[a]]
        T3[i] = ((uint32_t)s) | ((uint32_t)s << 8) | ((uint32_t)s3 << 16) | ((uint32_t)s2 << 24);
    }
    
    tables_initialized = 1;
}

// Inverse T-tables 초기화 함수 (복호화용)
static void init_inv_tables(void) {
    if (inv_tables_initialized) return;
    
    for (int i = 0; i < 256; i++) {
        uint8_t s = inv_s_box[i];
        uint8_t s9 = xtimes(xtimes(xtimes(s))) ^ s;      // 9·S[a]
        uint8_t s11 = xtimes(xtimes(xtimes(s))) ^ xtimes(s) ^ s;  // 11·S[a]
        uint8_t s13 = xtimes(xtimes(xtimes(s))) ^ xtimes(xtimes(s)) ^ s;  // 13·S[a]
        uint8_t s14 = xtimes(xtimes(xtimes(s))) ^ xtimes(xtimes(s)) ^ xtimes(s);  // 14·S[a]
        
        // Inverse MixColumns 행렬: [14, 11, 13, 9]
        // IT0[a] = [14·S[a], 9·S[a], 13·S[a], 11·S[a]]
        IT0[i] = ((uint32_t)s14) | ((uint32_t)s9 << 8) | ((uint32_t)s13 << 16) | ((uint32_t)s11 << 24);
        
        // IT1[a] = [11·S[a], 14·S[a], 9·S[a], 13·S[a]]
        IT1[i] = ((uint32_t)s11) | ((uint32_t)s14 << 8) | ((uint32_t)s9 << 16) | ((uint32_t)s13 << 24);
        
        // IT2[a] = [13·S[a], 11·S[a], 14·S[a], 9·S[a]]
        IT2[i] = ((uint32_t)s13) | ((uint32_t)s11 << 8) | ((uint32_t)s14 << 16) | ((uint32_t)s9 << 24);
        
        // IT3[a] = [9·S[a], 13·S[a], 11·S[a], 14·S[a]]
        IT3[i] = ((uint32_t)s9) | ((uint32_t)s13 << 8) | ((uint32_t)s11 << 16) | ((uint32_t)s14 << 24);
    }
    
    inv_tables_initialized = 1;
}

// --- AES의 4가지 기본 연산 ---
// AES는 16바이트(128비트) 데이터를 4x4 행렬(state)로 간주하고,
// 이 4가지 연산을 여러 라운드에 걸쳐 반복적으로 적용합니다.

/**
 * @brief SubBytes: state의 각 바이트를 S-Box를 이용해 치환합니다.
 * * T-tables 최적화: 단순히 S-Box를 사용합니다 (마지막 라운드에서만 사용).
 * @param state 4x4 크기의 데이터 블록
 */
static void SubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) state[i][j] = s_box[state[i][j]];
}

/**
 * @brief InvSubBytes: state의 각 바이트를 Inverse S-Box를 이용해 역치환합니다 (복호화용).
 * @param state 4x4 크기의 데이터 블록
 */
static void InvSubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) state[i][j] = inv_s_box[state[i][j]];
}

/**
 * @brief ShiftRows: state의 각 행을 정해진 규칙에 따라 왼쪽으로 이동시킵니다.
 * - 0행: 이동 없음
 * - 1행: 1칸 왼쪽 이동
 * - 2행: 2칸 왼쪽 이동
 * - 3행: 3칸 왼쪽 이동
 * 이 연산은 열(column) 단위로 묶여 있던 데이터들을 여러 열에 걸쳐 섞어주는 역할(확산 효과)을 합니다.
 * @param state 4x4 크기의 데이터 블록
 */
static void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    // 1행
    temp = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = temp;
    // 2행
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    // 3행
    temp = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = temp;
}

/**
 * @brief InvShiftRows: state의 각 행을 정해진 규칙에 따라 오른쪽으로 이동시킵니다 (복호화용).
 * - 0행: 이동 없음
 * - 1행: 1칸 오른쪽 이동
 * - 2행: 2칸 오른쪽 이동
 * - 3행: 3칸 오른쪽 이동
 * @param state 4x4 크기의 데이터 블록
 */
static void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    // 1행: 1칸 오른쪽 이동
    temp = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = temp;
    // 2행: 2칸 오른쪽 이동
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    // 3행: 3칸 오른쪽 이동
    temp = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = temp;
}

/**
 * @brief SubBytesAndMixColumns: T-tables를 사용하여 SubBytes와 MixColumns를 한 번에 수행합니다 (암호화용).
 * * T-tables 최적화: ShiftRows 후에 각 열에 대해 T-tables를 사용하여 SubBytes와 MixColumns를 동시에 수행합니다.
 * * 각 열 j에 대해: result = T0[s0] ^ T1[s1] ^ T2[s2] ^ T3[s3]
 * @param state 4x4 크기의 데이터 블록 (ShiftRows 후 상태)
 */
static void SubBytesAndMixColumns(uint8_t state[4][4]) {
    init_tables(); // T-tables 초기화 (최초 1회만 수행)
    
    for (int j = 0; j < 4; j++) {
        uint32_t result = T0[state[0][j]] ^ T1[state[1][j]] ^ T2[state[2][j]] ^ T3[state[3][j]];
        // 32비트 결과를 4바이트로 분리
        state[0][j] = (uint8_t)(result & 0xFF);
        state[1][j] = (uint8_t)((result >> 8) & 0xFF);
        state[2][j] = (uint8_t)((result >> 16) & 0xFF);
        state[3][j] = (uint8_t)((result >> 24) & 0xFF);
    }
}

/**
 * @brief InvSubBytesAndMixColumns: Inverse T-tables를 사용하여 InvSubBytes와 InvMixColumns를 한 번에 수행합니다 (복호화용).
 * * Inverse T-tables 최적화: InvShiftRows 후에 각 열에 대해 Inverse T-tables를 사용하여 InvSubBytes와 InvMixColumns를 동시에 수행합니다.
 * * 각 열 j에 대해: result = IT0[s0] ^ IT1[s1] ^ IT2[s2] ^ IT3[s3]
 * @param state 4x4 크기의 데이터 블록 (InvShiftRows 후 상태)
 */
static void InvSubBytesAndMixColumns(uint8_t state[4][4]) {
    init_inv_tables(); // Inverse T-tables 초기화 (최초 1회만 수행)
    
    for (int j = 0; j < 4; j++) {
        uint32_t result = IT0[state[0][j]] ^ IT1[state[1][j]] ^ IT2[state[2][j]] ^ IT3[state[3][j]];
        // 32비트 결과를 4바이트로 분리
        state[0][j] = (uint8_t)(result & 0xFF);
        state[1][j] = (uint8_t)((result >> 8) & 0xFF);
        state[2][j] = (uint8_t)((result >> 16) & 0xFF);
        state[3][j] = (uint8_t)((result >> 24) & 0xFF);
    }
}


/**
 * @brief AddRoundKey: state와 현재 라운드 키를 XOR 연산합니다.
 * @param state 4x4 크기의 데이터 블록
 * @param round_key 현재 라운드에서 사용할 16바이트 라운드 키
 */
static void AddRoundKey(uint8_t state[4][4], const uint8_t* round_key) {
    for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) state[j][i] ^= round_key[i * 4 + j];
}


// --- 키 스케줄링용 헬퍼 함수 ---
// 사용자가 제공한 마스터 키로부터 각 라운드에서 사용할 라운드 키들을 생성합니다.

static void RotWord(uint8_t* word) { // 4바이트(1워드)를 왼쪽으로 1바이트씩 순환
    uint8_t temp = word[0];
    word[0] = word[1]; word[1] = word[2]; word[2] = word[3]; word[3] = temp;
}

static void SubWord(uint8_t* word) { // 4바이트(1워드)의 각 바이트를 S-Box로 치환
    word[0] = s_box[word[0]]; word[1] = s_box[word[1]];
    word[2] = s_box[word[2]]; word[3] = s_box[word[3]];
}

/*****************************************************
 * 키 스케줄링(Key Expansion) 함수들
 * 마스터 키로부터 모든 라운드 키를 생성하여 AES_CTX에 저장합니다.
 * 키 길이에 따라 생성되는 라운드 키의 개수와 생성 방식이 약간씩 다릅니다.
 *****************************************************/
static void KeySchedule128(const uint8_t* key, AES_CTX* ctx) {
    uint8_t temp[4]; // 임시 4바이트 워드
    uint8_t* w = ctx->round_keys; // 생성된 라운드 키들이 저장될 배열
    memcpy(w, key, 16); // 첫 16바이트는 마스터 키 그대로 사용

    // 나머지 라운드 키 생성 (4워드씩 생성)
    for (int i = 4; i < 4 * (ctx->Nr + 1); i++) {
        memcpy(temp, &w[(i - 1) * 4], 4); // 이전 워드를 temp에 복사
        if (i % ctx->Nk == 0) { // 특정 조건(Nk의 배수)일 때
            RotWord(temp); // 워드 회전
            SubWord(temp); // S-Box 치환
            temp[0] ^= Rcon[i / ctx->Nk]; // 라운드 상수와 XOR
        }
        // 새 워드 = (i-Nk)번째 워드 XOR temp
        w[i * 4 + 0] = w[(i - ctx->Nk) * 4 + 0] ^ temp[0];
        w[i * 4 + 1] = w[(i - ctx->Nk) * 4 + 1] ^ temp[1];
        w[i * 4 + 2] = w[(i - ctx->Nk) * 4 + 2] ^ temp[2];
        w[i * 4 + 3] = w[(i - ctx->Nk) * 4 + 3] ^ temp[3];
    }
}

static void KeySchedule192(const uint8_t* key, AES_CTX* ctx) {
    uint8_t temp[4];
    uint8_t* w = ctx->round_keys;
    memcpy(w, key, 24); // 마스터 키 24바이트 복사

    for (int i = 6; i < 4 * (ctx->Nr + 1); i++) {
        memcpy(temp, &w[(i - 1) * 4], 4);
        if (i % ctx->Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[i / ctx->Nk];
        }
        w[i * 4 + 0] = w[(i - ctx->Nk) * 4 + 0] ^ temp[0];
        w[i * 4 + 1] = w[(i - ctx->Nk) * 4 + 1] ^ temp[1];
        w[i * 4 + 2] = w[(i - ctx->Nk) * 4 + 2] ^ temp[2];
        w[i * 4 + 3] = w[(i - ctx->Nk) * 4 + 3] ^ temp[3];
    }
}

static void KeySchedule256(const uint8_t* key, AES_CTX* ctx) {
    uint8_t temp[4];
    uint8_t* w = ctx->round_keys;
    memcpy(w, key, 32); // 마스터 키 32바이트 복사

    for (int i = 8; i < 4 * (ctx->Nr + 1); i++) {
        memcpy(temp, &w[(i - 1) * 4], 4);
        if (i % ctx->Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[i / ctx->Nk];
        } else if (i % ctx->Nk == 4) { // 256비트 키 스케줄에만 있는 추가 규칙
            SubWord(temp);
        }
        w[i * 4 + 0] = w[(i - ctx->Nk) * 4 + 0] ^ temp[0];
        w[i * 4 + 1] = w[(i - ctx->Nk) * 4 + 1] ^ temp[1];
        w[i * 4 + 2] = w[(i - ctx->Nk) * 4 + 2] ^ temp[2];
        w[i * 4 + 3] = w[(i - ctx->Nk) * 4 + 3] ^ temp[3];
    }
}


/*****************************************************
 * Crypto API 함수 구현
 * 헤더 파일(crypto_api.h)에 선언된 함수들을 실제로 구현하는 부분입니다.
 *****************************************************/

/**
 * @brief AES_set_key: 사용자가 제공한 마스터 키로 AES 컨텍스트를 초기화하고,
 * 모든 라운드 키를 미리 생성합니다.
 * @param ctx AES 상태를 저장할 컨텍스트 구조체 포인터
 * @param key 마스터 키
 * @param key_bits 키의 비트 길이 (128, 192, 256)
 * @return 성공 시 CRYPTO_SUCCESS, 실패 시 오류 코드
 */
CRYPTO_STATUS AES_set_key(AES_CTX* ctx, const uint8_t* key, int key_bits) {
    if (!ctx || !key) return CRYPTO_ERR_NULL_CONTEXT;
    
    ctx->key_bits = key_bits;
    ctx->Nk = key_bits / 32; // Nk: 키 길이를 32비트 워드 단위로 나타낸 값

    switch (key_bits) {
        case 128:
            ctx->Nr = AES_ROUND_128; // Nr: 라운드 수
            KeySchedule128(key, ctx);
            break;
        case 192:
            ctx->Nr = AES_ROUND_192;
            KeySchedule192(key, ctx);
            break;
        case 256:
            ctx->Nr = AES_ROUND_256;
            KeySchedule256(key, ctx);
            break;
        default:
            return CRYPTO_ERR_INVALID_ARGUMENT; // 지원하지 않는 키 길이
    }
    return CRYPTO_SUCCESS;
}

/**
 * @brief AES_encrypt_block: 16바이트 평문 블록 하나를 암호화합니다.
 * @param ctx 초기화된 AES 컨텍스트
 * @param in 16바이트 평문 블록
 * @param out 암호화된 결과가 저장될 16바이트 버퍼
 * @return 성공 시 CRYPTO_SUCCESS
 */
CRYPTO_STATUS AES_encrypt_block(const AES_CTX* ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) {
    if (!ctx || !in || !out) return CRYPTO_ERR_NULL_CONTEXT;
    
    // 초기화 여부 검증: AES_set_key가 호출되지 않았으면 에러
    if (ctx->Nr == 0 || ctx->key_bits == 0 || ctx->Nk == 0) {
        return CRYPTO_ERR_NOT_INITIALIZED;
    }

    // 1. 입력 평문을 4x4 state 행렬로 변환
    uint8_t state[4][4];
    for(int i=0; i<4; i++) for(int j=0; j<4; j++) state[j][i] = in[i*4+j];

    // 2. 초기 라운드: AddRoundKey
    AddRoundKey(state, ctx->round_keys);

    // 3. 메인 라운드: (Nr - 1)번 반복
    // T-tables 최적화: ShiftRows 후 SubBytesAndMixColumns를 한 번에 수행
    for (int r = 1; r < ctx->Nr; r++) {
        ShiftRows(state);
        SubBytesAndMixColumns(state); // T-tables 사용: SubBytes + MixColumns 동시 수행
        AddRoundKey(state, ctx->round_keys + r * 16); // r번째 라운드 키 사용
    }

    // 4. 마지막 라운드: MixColumns 제외
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, ctx->round_keys + ctx->Nr * 16);

    // 5. state 행렬을 출력 버퍼로 변환
    for(int i=0; i<4; i++) for(int j=0; j<4; j++) out[i*4+j] = state[j][i];
    return CRYPTO_SUCCESS;
}

/**
 * @brief AES_decrypt_block: 16바이트 암호문 블록 하나를 복호화합니다.
 * @param ctx 초기화된 AES 컨텍스트
 * @param in 16바이트 암호문 블록
 * @param out 복호화된 결과가 저장될 16바이트 버퍼
 * @return 성공 시 CRYPTO_SUCCESS
 */
CRYPTO_STATUS AES_decrypt_block(const AES_CTX* ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) {
    if (!ctx || !in || !out) return CRYPTO_ERR_NULL_CONTEXT;
    
    // 초기화 여부 검증: AES_set_key가 호출되지 않았으면 에러
    if (ctx->Nr == 0 || ctx->key_bits == 0 || ctx->Nk == 0) {
        return CRYPTO_ERR_NOT_INITIALIZED;
    }

    // 1. 입력 암호문을 4x4 state 행렬로 변환
    uint8_t state[4][4];
    for(int i=0; i<4; i++) for(int j=0; j<4; j++) state[j][i] = in[i*4+j];

    // 2. 초기 라운드: AddRoundKey (마지막 라운드 키 사용)
    AddRoundKey(state, ctx->round_keys + ctx->Nr * 16);

    // 3. 메인 라운드: (Nr - 1)번 반복 (역순)
    // T-tables 최적화: InvShiftRows 후 InvSubBytesAndMixColumns를 한 번에 수행
    for (int r = ctx->Nr - 1; r >= 1; r--) {
        InvShiftRows(state);
        InvSubBytesAndMixColumns(state); // Inverse T-tables 사용: InvSubBytes + InvMixColumns 동시 수행
        AddRoundKey(state, ctx->round_keys + r * 16); // r번째 라운드 키 사용
    }

    // 4. 마지막 라운드: InvMixColumns 제외
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, ctx->round_keys); // 초기 라운드 키 사용

    // 5. state 행렬을 출력 버퍼로 변환
    for(int i=0; i<4; i++) for(int j=0; j<4; j++) out[i*4+j] = state[j][i];
    return CRYPTO_SUCCESS;
}


/**
 * @brief AES_CTR_crypt: AES 카운터(CTR) 모드로 암호화 또는 복호화를 수행합니다.
 * * CTR 모드는 블록 암호인 AES를 스트림 암호처럼 사용할 수 있게 해줍니다.
 * Nonce(재사용 금지 값)와 Counter를 합쳐 암호화한 결과를 '키스트림'으로 만들고,
 * 이 키스트림을 평문(또는 암호문)과 XOR하여 암호문(또는 평문)을 생성합니다.
 * 암호화와 복호화 과정이 동일하다는 장점이 있습니다.
 * * @param ctx 초기화된 AES 컨텍스트
 * @param in 입력 데이터 (평문 또는 암호문)
 * @param length 입력 데이터의 길이 (바이트)
 * @param out 출력 데이터가 저장될 버퍼
 * @param nonce_counter 16바이트 Nonce+Counter 블록. 함수 호출 후 자동으로 1씩 증가합니다.
 * @return 성공 시 CRYPTO_SUCCESS
 */
CRYPTO_STATUS AES_CTR_crypt(const AES_CTX* ctx, const uint8_t* in, size_t length, uint8_t* out, uint8_t nonce_counter[AES_BLOCK_SIZE]) {
    if (!ctx) return CRYPTO_ERR_NULL_CONTEXT;
    if ((!in || !out) && length > 0) return CRYPTO_ERR_INVALID_INPUT;
    if (!nonce_counter) return CRYPTO_ERR_INVALID_INPUT;
    
    // 초기화 여부 검증: AES_set_key가 호출되지 않았으면 에러
    if (ctx->Nr == 0 || ctx->key_bits == 0 || ctx->Nk == 0) {
        return CRYPTO_ERR_NOT_INITIALIZED;
    }
    
    uint8_t counter_block[AES_BLOCK_SIZE]; // 현재 카운터 값 (암호화 대상)
    uint8_t keystream_block[AES_BLOCK_SIZE]; // 카운터를 암호화한 결과 (키스트림)
    size_t offset = 0;

    memcpy(counter_block, nonce_counter, AES_BLOCK_SIZE);

    // 데이터를 16바이트 블록 단위로 처리
    while (length > 0) {
        // 1. 현재 카운터 블록을 AES로 암호화하여 키스트림 생성
        AES_encrypt_block(ctx, counter_block, keystream_block);

        // 처리할 데이터 길이 결정 (마지막 블록은 16바이트보다 작을 수 있음)
        size_t block_len = (length < AES_BLOCK_SIZE) ? length : AES_BLOCK_SIZE;

        // 2. 입력 데이터와 키스트림을 XOR하여 출력 생성
        for (size_t i = 0; i < block_len; i++) {
            out[offset + i] = in[offset + i] ^ keystream_block[i];
        }

        length -= block_len;
        offset += block_len;
        
        // 3. 다음 블록을 위해 카운터 값을 1 증가 (big-endian 방식)
        for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
            if (++counter_block[i] != 0) break; // 자리올림이 없으면 중단
        }
    }
    
    // 최종적으로 증가된 카운터 값을 원래 nonce_counter 배열에 업데이트
    memcpy(nonce_counter, counter_block, AES_BLOCK_SIZE); 
    return CRYPTO_SUCCESS;
}

#ifdef PLATFORM_MAC
// OpenSSL 동적 로딩 관련 전역 변수
static void* g_openssl_handle = NULL;
static int (*g_rand_bytes)(unsigned char*, int) = NULL;
static int g_openssl_checked = 0;

// OpenSSL 라이브러리 경로 목록 (macOS에서 일반적인 경로들)
static const char* openssl_paths[] = {
    "/opt/homebrew/lib/libcrypto.dylib",      // Apple Silicon Homebrew
    "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",  // OpenSSL 3.x
    "/opt/homebrew/opt/openssl@1.1/lib/libcrypto.dylib", // OpenSSL 1.1.x
    "/usr/local/lib/libcrypto.dylib",          // Intel Homebrew
    "/usr/local/opt/openssl/lib/libcrypto.dylib", // Intel Homebrew (구버전)
    "/usr/lib/libcrypto.dylib",                // 시스템 (일반적으로 없음)
    NULL
};

// OpenSSL 동적 로딩 함수
static int load_openssl_mac(void) {
    if (g_openssl_checked) {
        return (g_rand_bytes != NULL) ? 1 : 0;
    }
    
    g_openssl_checked = 1;
    
    // 각 경로를 시도
    for (int i = 0; openssl_paths[i] != NULL; i++) {
        g_openssl_handle = dlopen(openssl_paths[i], RTLD_LAZY);
        if (g_openssl_handle) {
            // RAND_bytes 함수 포인터 가져오기
            g_rand_bytes = (int (*)(unsigned char*, int))dlsym(g_openssl_handle, "RAND_bytes");
            if (g_rand_bytes) {
                printf("[INFO] OpenSSL loaded from: %s\n", openssl_paths[i]);
                return 1;
            }
            // 함수를 찾지 못하면 핸들 닫기
            dlclose(g_openssl_handle);
            g_openssl_handle = NULL;
#ifndef NDEBUG
            printf("[DEBUG] RAND_bytes not found in: %s\n", openssl_paths[i]);
#endif
        } else {
            // dlopen 실패 시 에러 메시지 출력 (디버깅용)
#ifndef NDEBUG
            const char* error = dlerror();
            if (error) {
                printf("[DEBUG] Failed to load %s: %s\n", openssl_paths[i], error);
            }
#endif
        }
    }
    
    printf("[WARNING] OpenSSL not found. Using fallback random number generator.\n");
    printf("[INFO] To install OpenSSL: brew install openssl\n");
    return 0;
}
#endif

/**
 * @brief crypto_random_bytes: OpenSSL RAND_bytes를 사용하여 암호학적으로 안전한 난수를 생성합니다.
 * @param buf 난수를 저장할 버퍼
 * @param len 생성할 난수의 바이트 수
 * @return 성공 시 CRYPTO_SUCCESS, 실패 시 CRYPTO_ERR_INTERNAL_FAILURE
 * @note macOS에서는 런타임에 OpenSSL을 동적으로 로드합니다.
 *       다른 플랫폼에서는 컴파일 시 -DUSE_OPENSSL 플래그와 OpenSSL 라이브러리 링크가 필요합니다.
 */
CRYPTO_STATUS crypto_random_bytes(uint8_t* buf, size_t len) {
    if (!buf && len > 0) return CRYPTO_ERR_INVALID_INPUT;
    if (len == 0) return CRYPTO_SUCCESS;

#ifdef USE_OPENSSL
    // 컴파일 타임에 OpenSSL이 링크된 경우
    if (RAND_bytes(buf, (int)len) == 1) {
        return CRYPTO_SUCCESS;
    } else {
        return CRYPTO_ERR_INTERNAL_FAILURE;
    }
#elif defined(PLATFORM_MAC)
    // macOS: OpenSSL을 동적으로 로드 시도
    if (load_openssl_mac() && g_rand_bytes) {
        if (g_rand_bytes(buf, (int)len) == 1) {
            return CRYPTO_SUCCESS;
        } else {
            return CRYPTO_ERR_INTERNAL_FAILURE;
        }
    }
    // OpenSSL을 찾지 못한 경우
    return CRYPTO_ERR_INTERNAL_FAILURE;
#else
    // 다른 플랫폼 (Windows 등)
    (void)buf;  // unused parameter warning 방지
    (void)len;
    return CRYPTO_ERR_INTERNAL_FAILURE;
#endif
}
