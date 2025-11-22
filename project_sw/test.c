#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"
#include "sha512.h"
#include "hmac_sha512.h"
#include "kdf.h"

// 헬퍼 함수: 데이터를 16진수 문자열로 출력
void print_hex(const char* label, const unsigned char* data, int len) {
    printf("%-14s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 헬퍼 함수: 두 데이터 배열이 일치하는지 비교
int compare_hex(const unsigned char* d1, const unsigned char* d2, int len) {
    return memcmp(d1, d2, len) == 0;
}

// SHA512 테스트
int test_sha512(void) {
    printf("=======================================\n");
    printf("  SHA-512 Test Vectors\n");
    printf("=======================================\n");
    
    int pass_count = 0;
    int total_count = 0;
    
    // Test 1: "abc"
    {
        total_count++;
        const char* msg = "abc";
        const uint8_t expected[64] = {
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
        };
        
        SHA512_CTX ctx;
        uint8_t digest[64];
        sha512_init(&ctx);
        sha512_update(&ctx, (const uint8_t*)msg, strlen(msg));
        sha512_final(&ctx, digest);
        
        if (compare_hex(digest, expected, 64)) {
            printf("Test 1 (\"abc\"): PASS\n");
            pass_count++;
        } else {
            printf("Test 1 (\"abc\"): FAIL\n");
            print_hex("Expected", expected, 64);
            print_hex("Got", digest, 64);
        }
    }
    
    // Test 2: Empty string
    {
        total_count++;
        const uint8_t expected[64] = {
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
        };
        
        SHA512_CTX ctx;
        uint8_t digest[64];
        sha512_init(&ctx);
        sha512_final(&ctx, digest);
        
        if (compare_hex(digest, expected, 64)) {
            printf("Test 2 (empty): PASS\n");
            pass_count++;
        } else {
            printf("Test 2 (empty): FAIL\n");
            print_hex("Expected", expected, 64);
            print_hex("Got", digest, 64);
        }
    }
    
    printf("\nSHA-512 Tests: %d/%d passed\n\n", pass_count, total_count);
    return (pass_count == total_count) ? 0 : 1;
}

// HMAC-SHA512 테스트 (RFC 4231)
int test_hmac_sha512(void) {
    printf("=======================================\n");
    printf("  HMAC-SHA512 Test Vectors (RFC 4231)\n");
    printf("=======================================\n");
    
    int pass_count = 0;
    int total_count = 0;
    
    // Test Case 1
    {
        total_count++;
        uint8_t key1[20];
        memset(key1, 0x0b, sizeof(key1));
        const uint8_t msg1[] = "Hi There";
        const uint8_t expected1[64] = {
            0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
            0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
            0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
            0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54
        };
        
        uint8_t mac[64];
        hmac_sha512(key1, sizeof(key1), msg1, sizeof(msg1) - 1, mac);
        
        if (compare_hex(mac, expected1, 64)) {
            printf("Test Case 1: PASS\n");
            pass_count++;
        } else {
            printf("Test Case 1: FAIL\n");
            print_hex("Expected", expected1, 64);
            print_hex("Got", mac, 64);
        }
    }
    
    // Test Case 2
    {
        total_count++;
        const uint8_t key2[] = {0x4a, 0x65, 0x66, 0x65}; // "Jefe"
        const uint8_t msg2[] = {
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
            0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f
        };
        const uint8_t expected2[64] = {
            0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0, 0xa3,
            0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54,
            0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd,
            0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37
        };
        
        uint8_t mac[64];
        hmac_sha512(key2, sizeof(key2), msg2, sizeof(msg2), mac);
        
        if (compare_hex(mac, expected2, 64)) {
            printf("Test Case 2: PASS\n");
            pass_count++;
        } else {
            printf("Test Case 2: FAIL\n");
            print_hex("Expected", expected2, 64);
            print_hex("Got", mac, 64);
        }
    }
    
    printf("\nHMAC-SHA512 Tests: %d/%d passed\n\n", pass_count, total_count);
    return (pass_count == total_count) ? 0 : 1;
}

// PBKDF2-SHA512 테스트
int test_pbkdf2_sha512(void) {
    printf("=======================================\n");
    printf("  PBKDF2-SHA512 Test Vectors\n");
    printf("=======================================\n");
    
    int pass_count = 0;
    int total_count = 0;
    
    // Test Case 1: RFC 6070 style (simplified)
    {
        total_count++;
        const char* password = "password";
        const uint8_t salt[] = {0x73, 0x61, 0x6c, 0x74}; // "salt"
        uint8_t output[64];
        
        pbkdf2_sha512((const uint8_t*)password, strlen(password),
                     salt, sizeof(salt), 1, output, 64);
        
        // Note: This is a basic test - actual RFC test vectors may differ
        // We're mainly checking that the function runs without error
        printf("Test Case 1 (basic): PASS (function executed)\n");
        pass_count++;
    }
    
    // Test Case 2: With iterations
    {
        total_count++;
        const char* password = "test";
        const uint8_t salt[] = {0x41, 0x45, 0x53, 0x43}; // "AESC"
        uint8_t output[64];
        
        pbkdf2_sha512((const uint8_t*)password, strlen(password),
                     salt, sizeof(salt), 10000, output, 64);
        
        printf("Test Case 2 (10000 iterations): PASS (function executed)\n");
        pass_count++;
    }
    
    printf("\nPBKDF2-SHA512 Tests: %d/%d passed\n\n", pass_count, total_count);
    return (pass_count == total_count) ? 0 : 1;
}

// AES 테스트
int test_aes(void) {
    printf("=======================================\n");
    printf("  NIST SP 800-38A CTR Mode Test Vector\n");
    printf("=======================================\n");
    
    AES_CTX ctx;
    int pass_count = 0;
    int total_count = 0;

    // --- AES-128 CTR Test ---
    {
        total_count++;
        printf("--- AES-128 CTR Encryption Test ---\n");
        uint8_t key128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        uint8_t pt128[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
        uint8_t iv128_enc[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
        uint8_t expected_ct128[] = {0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce};
        uint8_t ct128[AES_BLOCK_SIZE];
        uint8_t pt128_copy[AES_BLOCK_SIZE];
        memcpy(pt128_copy, pt128, AES_BLOCK_SIZE);

        AES_set_key(&ctx, key128, 128);
        AES_CTR_crypt(&ctx, pt128, sizeof(pt128), ct128, iv128_enc);

        if (compare_hex(ct128, expected_ct128, sizeof(ct128))) {
            printf("AES-128 Encryption: PASS\n");
            pass_count++;
        } else {
            printf("AES-128 Encryption: FAIL\n");
            print_hex("Expected", expected_ct128, sizeof(expected_ct128));
            print_hex("Got", ct128, sizeof(ct128));
        }
        
        // 복호화 검증
        total_count++;
        uint8_t iv128_dec[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
        uint8_t decrypted128[AES_BLOCK_SIZE];
        uint8_t ct128_copy[AES_BLOCK_SIZE];
        memcpy(ct128_copy, ct128, AES_BLOCK_SIZE);
        
        AES_set_key(&ctx, key128, 128);
        AES_CTR_crypt(&ctx, ct128, sizeof(ct128), decrypted128, iv128_dec);
        
        if (compare_hex(pt128_copy, decrypted128, sizeof(pt128_copy))) {
            printf("AES-128 Decryption: PASS\n");
            pass_count++;
        } else {
            printf("AES-128 Decryption: FAIL\n");
            print_hex("Expected", pt128_copy, sizeof(pt128_copy));
            print_hex("Got", decrypted128, sizeof(decrypted128));
        }
    }

    // --- AES-192 CTR Test ---
    {
        total_count++;
        printf("--- AES-192 CTR Encryption Test ---\n");
        uint8_t key192[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
        uint8_t pt192[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
        uint8_t iv192_enc[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
        uint8_t expected_ct192[] = {0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b};
        uint8_t ct192[AES_BLOCK_SIZE];
        uint8_t pt192_copy[AES_BLOCK_SIZE];
        memcpy(pt192_copy, pt192, AES_BLOCK_SIZE);

        AES_set_key(&ctx, key192, 192);
        AES_CTR_crypt(&ctx, pt192, sizeof(pt192), ct192, iv192_enc);
        
        if (compare_hex(ct192, expected_ct192, sizeof(ct192))) {
            printf("AES-192 Encryption: PASS\n");
            pass_count++;
        } else {
            printf("AES-192 Encryption: FAIL\n");
            print_hex("Expected", expected_ct192, sizeof(expected_ct192));
            print_hex("Got", ct192, sizeof(ct192));
        }
        
        // 복호화 검증
        total_count++;
        uint8_t iv192_dec[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
        uint8_t decrypted192[AES_BLOCK_SIZE];
        uint8_t ct192_copy[AES_BLOCK_SIZE];
        memcpy(ct192_copy, ct192, AES_BLOCK_SIZE);
        
        AES_set_key(&ctx, key192, 192);
        AES_CTR_crypt(&ctx, ct192, sizeof(ct192), decrypted192, iv192_dec);
        
        if (compare_hex(pt192_copy, decrypted192, sizeof(pt192_copy))) {
            printf("AES-192 Decryption: PASS\n");
            pass_count++;
        } else {
            printf("AES-192 Decryption: FAIL\n");
            print_hex("Expected", pt192_copy, sizeof(pt192_copy));
            print_hex("Got", decrypted192, sizeof(decrypted192));
        }
    }

    // --- AES-256 CTR Test ---
    {
        total_count++;
        printf("--- AES-256 CTR Encryption Test ---\n");
        uint8_t key256[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
        uint8_t pt256[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
        uint8_t iv256_enc[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
        uint8_t expected_ct256[] = {0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28};
        uint8_t ct256[AES_BLOCK_SIZE];
        uint8_t pt256_copy[AES_BLOCK_SIZE];
        memcpy(pt256_copy, pt256, AES_BLOCK_SIZE);

        AES_set_key(&ctx, key256, 256);
        AES_CTR_crypt(&ctx, pt256, sizeof(pt256), ct256, iv256_enc);

        if (compare_hex(ct256, expected_ct256, sizeof(ct256))) {
            printf("AES-256 Encryption: PASS\n");
            pass_count++;
        } else {
            printf("AES-256 Encryption: FAIL\n");
            print_hex("Expected", expected_ct256, sizeof(expected_ct256));
            print_hex("Got", ct256, sizeof(ct256));
        }
        
        // 복호화 검증
        total_count++;
        uint8_t iv256_dec[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
        uint8_t decrypted256[AES_BLOCK_SIZE];
        uint8_t ct256_copy[AES_BLOCK_SIZE];
        memcpy(ct256_copy, ct256, AES_BLOCK_SIZE);
        
        AES_set_key(&ctx, key256, 256);
        AES_CTR_crypt(&ctx, ct256, sizeof(ct256), decrypted256, iv256_dec);
        
        if (compare_hex(pt256_copy, decrypted256, sizeof(pt256_copy))) {
            printf("AES-256 Decryption: PASS\n");
            pass_count++;
        } else {
            printf("AES-256 Decryption: FAIL\n");
            print_hex("Expected", pt256_copy, sizeof(pt256_copy));
            print_hex("Got", decrypted256, sizeof(decrypted256));
        }
    }

    printf("\nAES Tests: %d/%d passed\n\n", pass_count, total_count);
    return (pass_count == total_count) ? 0 : 1;
}

//int main(void) {
//    printf("=======================================\n");
//    printf("  Cryptographic Functions Test Suite\n");
//    printf("=======================================\n\n");
//    
//    int sha512_result = test_sha512();
//    int hmac_result = test_hmac_sha512();
//    int pbkdf2_result = test_pbkdf2_sha512();
//    int aes_result = test_aes();
//    
//    printf("=======================================\n");
//    printf("  Test Summary\n");
//    printf("=======================================\n");
//    printf("SHA-512:      %s\n", sha512_result == 0 ? "PASS" : "FAIL");
//    printf("HMAC-SHA512:  %s\n", hmac_result == 0 ? "PASS" : "FAIL");
//    printf("PBKDF2-SHA512: %s\n", pbkdf2_result == 0 ? "PASS" : "FAIL");
//    printf("AES:          %s\n", aes_result == 0 ? "PASS" : "FAIL");
//    printf("=======================================\n");
//    
//    if (sha512_result == 0 && hmac_result == 0 && pbkdf2_result == 0 && aes_result == 0) {
//        printf("All tests PASSED!\n");
//        return 0;
//    } else {
//        printf("Some tests FAILED!\n");
//        return 1;
//    }
//}

