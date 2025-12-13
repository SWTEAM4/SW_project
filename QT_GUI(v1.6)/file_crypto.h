#ifndef FILE_CRYPTO_H
#define FILE_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// .enc 파일 헤더 구조
#define ENC_SIGNATURE "AESC"
#define ENC_VERSION 0x02
#define ENC_MODE_CTR 0x02
#define ENC_HMAC_ENABLED 0x01
#define ENC_HEADER_SIZE 56
#define ENC_NONCE_SIZE 8
#define ENC_SALT_SIZE 16
#define ENC_HMAC_SIZE 64

// 키 길이 코드 상수
#define KEY_LENGTH_CODE_128 0x01
#define KEY_LENGTH_CODE_192 0x02
#define KEY_LENGTH_CODE_256 0x03

// 파일 버퍼 크기 (512KB)
#define FILE_BUFFER_SIZE (512 * 1024)

// HMAC 키 길이
#define HMAC_KEY_SIZE 24

// 사용자 입력 버퍼 크기
#define MAX_PATH_LENGTH 512
#define MAX_FILENAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 32

// scanf 제한 (null terminator를 위한 -1)
#define SCANF_PATH_FORMAT "%511s"
#define SCANF_FILENAME_FORMAT "%255s"
#define SCANF_PASSWORD_FORMAT "%31s"

// 파일 암호화/복호화 에러 코드
typedef enum {
    FILE_CRYPTO_SUCCESS = 0,                    // 성공: 작업이 정상적으로 완료됨
    
    // 파일 I/O 관련 에러
    FILE_CRYPTO_ERR_FILE_OPEN,                   // 파일 열기 실패: 입력/출력 파일을 열 수 없음 (권한 없음, 파일 없음 등)
    FILE_CRYPTO_ERR_FILE_READ,                   // 파일 읽기 실패: 파일에서 데이터를 읽는 중 오류 발생
    FILE_CRYPTO_ERR_FILE_WRITE,                  // 파일 쓰기 실패: 파일에 데이터를 쓰는 중 오류 발생
    FILE_CRYPTO_ERR_FILE_SIZE,                   // 파일 크기 오류: 파일 크기가 유효하지 않거나 음수
    
    // 헤더 관련 에러
    FILE_CRYPTO_ERR_INVALID_HEADER,              // 잘못된 헤더: 헤더를 읽을 수 없거나 형식이 맞지 않음
    FILE_CRYPTO_ERR_INVALID_SIGNATURE,           // 잘못된 시그니처: 파일 시그니처("AESC")가 일치하지 않음
    FILE_CRYPTO_ERR_UNSUPPORTED_VERSION,         // 지원하지 않는 버전: 파일 버전이 현재 지원하는 버전과 다름
    FILE_CRYPTO_ERR_UNSUPPORTED_KEY_LENGTH,      // 지원하지 않는 키 길이: AES 키 길이 코드가 유효하지 않음 (128/192/256 외)
    
    // 암호화/복호화 연산 에러
    FILE_CRYPTO_ERR_ENCRYPTION_FAILED,           // 암호화 실패: AES 암호화 연산 중 오류 발생
    FILE_CRYPTO_ERR_DECRYPTION_FAILED,           // 복호화 실패: AES 복호화 연산 중 오류 발생
    
    // HMAC 관련 에러
    FILE_CRYPTO_ERR_HMAC_VERIFICATION_FAILED,    // HMAC 검증 실패: 저장된 HMAC과 계산된 HMAC이 일치하지 않음 (파일 손상 또는 잘못된 비밀번호)
    
    // 메모리 관련 에러
    FILE_CRYPTO_ERR_MEMORY_ALLOCATION,           // 메모리 할당 실패: 버퍼 할당 중 메모리 부족
    
    // 임시 파일 관련 에러
    FILE_CRYPTO_ERR_TEMP_FILE_CREATE,            // 임시 파일 생성 실패: 복호화 중 임시 파일을 생성할 수 없음
    
    // 입력 검증 에러
    FILE_CRYPTO_ERR_INVALID_PASSWORD,            // 잘못된 비밀번호: 비밀번호 형식이 올바르지 않음 (validate_password 실패)
    FILE_CRYPTO_ERR_INVALID_INPUT               // 잘못된 입력: 함수 파라미터가 NULL이거나 유효하지 않음
} FILE_CRYPTO_STATUS;

// 헤더 구조
typedef struct {
    uint8_t signature[4];      // [0:4] "AESC"
    uint8_t version;           // [4:5] 0x02 (current)
    uint8_t key_length_code;   // [5:6] 0x01=128, 0x02=192, 0x03=256
    uint8_t mode_code;         // [6:7] 0x02=CTR
    uint8_t hmac_enabled;      // [7:8] 0x01=enabled
    uint8_t nonce[8];          // [8:16] Nonce
    uint8_t format[8];         // [16:24] Original file extension/signature (e.g., ".hwp", ".png", ".jpeg", ".txt")
    uint8_t salt[16];          // [24:40] PBKDF2 salt (16 bytes)
    uint8_t reserved[16];      // [40:56] Reserved for future use
} EncFileHeader;

// 진행률 콜백 함수 타입
typedef void (*progress_callback_t)(long processed, long total, void* user_data);

// 파일 암호화
int encrypt_file(const char* input_path, const char* output_path,
                 int aes_key_bits, const char* password);

// 파일 암호화 (진행률 콜백 지원)
int encrypt_file_with_progress(const char* input_path, const char* output_path,
                               int aes_key_bits, const char* password,
                               progress_callback_t progress_cb, void* user_data);

// 파일 복호화
int decrypt_file(const char* input_path, const char* output_path,
                 const char* password, char* final_output_path, size_t final_path_size);

// 파일 복호화 (진행률 콜백 지원)
int decrypt_file_with_progress(const char* input_path, const char* output_path,
                               const char* password, char* final_output_path, size_t final_path_size,
                               progress_callback_t progress_cb, void* user_data);

// 헤더에서 AES 키 길이 읽기
int read_aes_key_length(const char* input_path);

#ifdef __cplusplus
}
#endif

#endif // FILE_CRYPTO_H


