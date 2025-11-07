#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include "crypto_api.h"
#include "hmac_sha512.h"
#include <time.h>
static double now_sec(void) { return (double)clock() / CLOCKS_PER_SEC; }

/* 외부 테스트 엔트리 (기존과 동일) */
int test_aes(void);     /* 성공 시 0 */
int test_sha512(void);  /* 성공 시 0 */

// ====== [HMAC-SHA512] 고해상도 타이머 ======
#ifdef _WIN32
#include <windows.h>
static double now_ms(void) {
    static LARGE_INTEGER freq = { 0 };
    LARGE_INTEGER t;
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1000.0 / (double)freq.QuadPart;
}
#else
#include <time.h>
static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}
#endif

int main(void)
{
    printf("=======================================\n");
    printf("       CRYPTO FUNCTION TEST START      \n");
    printf("=======================================\n\n");

    printf("[1] AES CTR Mode Test 시작\n");
    if (test_aes() == 0)  printf("[AES] 모든 AES CTR Mode 테스트 벡터 통과!\n\n");
    else                  printf("[AES] AES CTR Mode 테스트 실패!\n\n");

    printf("[2] SHA-512 Test 시작...\n");
    if (test_sha512() == 0) printf("[SHA512] 모든 SHA-512 테스트 벡터 통과!\n\n");
    else                     printf("[SHA512] SHA-512 테스트 실패!\n\n");

    // ----- HMAC-SHA512 요약 테스트 -----
    printf("[3] HMAC-SHA512 Self-Test 시작...\n");

    int passed = 0, total = 0, failed_case = -1;
    double t0 = now_ms();
    int ok = hmac_sha512_selftest_summary(&passed, &total, &failed_case);
    double t1 = now_ms();

    printf("테스트 완료: %d 중 %d 통과\n", total, passed);
    printf("총 실행 시간: %.6f초 (%.3f ms)\n", (t1 - t0) / 1000.0, (t1 - t0));

    if (ok) {
        printf("HMAC-SHA512 테스트 통과!\n");
    }
    else {
        if (failed_case > 0)
            printf("HMAC-SHA512 테스트 실패! (실패 TC=%d)\n", failed_case);
        else
            printf("HMAC-SHA512 테스트 실패!\n");
    }

    printf("=======================================\n");
    printf("        모든 CRYPTO TEST 완료!         \n");
    printf("=======================================\n");
    return ok ? 0 : 1;
}
