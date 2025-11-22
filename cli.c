#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "crypto_api.h"
#include "aes.h"
#include "sha512.h"
#include "hmac_sha512.h"
#include "kdf.h"
#include "file_crypto.h"
#include "platform_utils.h"


#ifdef PLATFORM_WINDOWS
#include <windows.h>
#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
#endif

// 청크 크기 정의 (64KB)
#define FILE_CHUNK_SIZE (64 * 1024)

// 패스워드 검증 (영문+숫자, 대소문자, 최대 10자)
int validate_password(const char* password) {
    if (!password) return 0;
    size_t len = strlen(password);
    if (len == 0 || len > 10) return 0;
    
    for (size_t i = 0; i < len; i++) {
        char c = password[i];
        if (!((c >= 'A' && c <= 'Z') || 
              (c >= 'a' && c <= 'z') || 
              (c >= '0' && c <= '9'))) {
            return 0;
        }
    }
    return 1;
}

// 키 도출: PBKDF2-SHA512 -> AES 키 + HMAC 키
void derive_keys(const char* password, int aes_key_bits, 
                 uint8_t* aes_key, uint8_t* hmac_key) {
    // 1. 패스워드를 PBKDF2-SHA512로 512비트(64바이트)로 변환
    uint8_t kdf_output[64];
    pbkdf2_sha512((const uint8_t*)password, strlen(password),
                  NULL, 0, 10000, kdf_output, 64);
    
    // 2. 상위 절반(32바이트)에서 AES 키 길이만큼 사용
    int aes_key_bytes = aes_key_bits / 8;
    memcpy(aes_key, kdf_output, aes_key_bytes);
    
    // 3. 하위 32바이트 중 처음 24바이트를 HMAC 키로 사용
    memcpy(hmac_key, kdf_output + 32, 24);
}

// 랜덤 nonce 생성 (OpenSSL RAND_bytes 사용)
int generate_nonce(uint8_t* nonce, size_t len) {
    if (crypto_random_bytes(nonce, len) == CRYPTO_SUCCESS) {
        printf("[DEBUG] OpenSSL RAND_bytes random number generation succeeded\n");
        return 1;
    }
    // Fallback if OpenSSL is not available (not recommended for security)
    // srand is already called in main function
    printf("[DEBUG] OpenSSL RAND_bytes failed, using fallback rand()\n");
    for (size_t i = 0; i < len; i++) {
        nonce[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0; // indicates fallback was used
}

// Extract extension from file path (e.g., "file.txt" -> ".txt")
// Returns empty string if no extension
void extract_extension(const char* file_path, char* ext, size_t ext_size) {
    if (!file_path || !ext || ext_size == 0) {
        if (ext && ext_size > 0) ext[0] = '\0';
        return;
    }
    
    const char* last_dot = strrchr(file_path, '.');
    const char* last_slash = strrchr(file_path, '/');
#ifdef _WIN32
    const char* last_backslash = strrchr(file_path, '\\');
    if (last_backslash && (!last_slash || last_backslash > last_slash)) {
        last_slash = last_backslash;
    }
#endif
    
    if (last_dot && (!last_slash || last_dot > last_slash)) {
        size_t ext_len = strlen(last_dot);
        if (ext_len < ext_size) {
            strncpy(ext, last_dot, ext_size - 1);
            ext[ext_size - 1] = '\0';
        } else {
            ext[0] = '\0';
        }
    } else {
        ext[0] = '\0';
    }
}

// Progress display function
static void print_progress(long processed, long total, const char* operation) {
    if (total <= 0) return;
    
    double percent = (double)processed / total * 100.0;
    if (percent > 100.0) percent = 100.0;
    
    // Progress bar length (50 characters)
    int bar_width = 50;
    int filled = (int)(percent / 100.0 * bar_width);
    
    printf("\r%s [", operation);
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) {
            printf("=");
        } else if (i == filled) {
            printf(">");
        } else {
            printf(" ");
        }
    }
    printf("] %.1f%% (%ld / %ld bytes)", percent, processed, total);
    fflush(stdout);
}

// Internal implementation function (with callback support)
static int encrypt_file_internal(const char* input_path, const char* output_path,
                                 int aes_key_bits, const char* password,
                                 progress_callback_t progress_cb, void* user_data) {
    FILE* fin = platform_fopen(input_path, "rb");
    if (!fin) {
        if (!progress_cb) printf("Error: Cannot open file: %s\n", input_path);
        return 0;
    }
    
    // 파일 크기 확인
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    if (file_size < 0) {
        fclose(fin);
        return 0;
    }
    
    if (!progress_cb) printf("Encrypting...\n");
    
    // 키 도출
    uint8_t aes_key[32];
    uint8_t hmac_key[24];
    derive_keys(password, aes_key_bits, aes_key, hmac_key);
    
    // AES 컨텍스트 설정
    AES_CTX aes_ctx;
    if (AES_set_key(&aes_ctx, aes_key, aes_key_bits) != CRYPTO_SUCCESS) {
        fclose(fin);
        return 0;
    }
    
    // Generate nonce
    uint8_t nonce[8];
    generate_nonce(nonce, 8);
    
    // nonce_counter for CTR mode (8-byte nonce + 8-byte counter)
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, nonce, 8);
    memset(nonce_counter + 8, 0, 8);
    
    // Extract original file extension and store in header
    char original_ext[16];
    extract_extension(input_path, original_ext, sizeof(original_ext));
    size_t ext_len = strlen(original_ext);
    if (ext_len > 7) ext_len = 7; // Maximum 7 bytes (reserve space for null terminator in format[8])
    
    // Write header
    EncFileHeader header;
    memcpy(header.signature, ENC_SIGNATURE, 4);
    header.version = ENC_VERSION;
    header.key_length_code = (aes_key_bits == 128) ? 0x01 : 
                             (aes_key_bits == 192) ? 0x02 : 0x03;
    header.mode_code = ENC_MODE_CTR;
    header.hmac_enabled = ENC_HMAC_ENABLED;
    memcpy(header.nonce, nonce, 8);
    memset(header.format, 0, 8);
    // Store extension string in format (e.g., ".hwp", ".png", ".jpeg", ".txt")
    if (ext_len > 0) {
        memcpy(header.format, original_ext, ext_len);
    }
    memset(header.reserved, 0, 16);
    
    // Initialize HMAC (generated from header + original file)
    HMAC_SHA512_CTX hmac_ctx;
    hmac_sha512_init(&hmac_ctx, hmac_key, 24);
    hmac_sha512_update(&hmac_ctx, (uint8_t*)&header, sizeof(header));  // 헤더를 HMAC에 포함
    
    // Read original file and update HMAC (plaintext)
    uint8_t plaintext_buffer[FILE_CHUNK_SIZE];
    size_t bytes_read;
    long total_processed = 0;
    
    // Save position to read file from beginning again
    long file_pos = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    while ((bytes_read = fread(plaintext_buffer, 1, FILE_CHUNK_SIZE, fin)) > 0) {
        // Update HMAC (for original file plaintext)
        hmac_sha512_update(&hmac_ctx, plaintext_buffer, bytes_read);
    }
    
    // HMAC 최종 계산
    uint8_t hmac[64];
    hmac_sha512_final(&hmac_ctx, hmac);
    
    // Reset file position to beginning
    fseek(fin, 0, SEEK_SET);
    
    // 출력 파일 작성
    FILE* fout = platform_fopen(output_path, "wb");
    if (!fout) {
        fclose(fin);
        return 0;
    }
    
    // Write header
    fwrite(&header, 1, sizeof(header), fout);
    
    // Write HMAC (after header)
    fwrite(hmac, 1, 64, fout);
    
    // Read file in chunks, encrypt, and write
    uint8_t buffer[FILE_CHUNK_SIZE];
    int success = 1;
    
    while ((bytes_read = fread(buffer, 1, FILE_CHUNK_SIZE, fin)) > 0) {
        // Encrypt chunk (in-place)
        if (AES_CTR_crypt(&aes_ctx, buffer, bytes_read, buffer, nonce_counter) != CRYPTO_SUCCESS) {
            success = 0;
            break;
        }
        
        // Write ciphertext
        if (fwrite(buffer, 1, bytes_read, fout) != bytes_read) {
            success = 0;
            break;
        }
        
        // 진행률 업데이트 - 콜백이 있으면 콜백, 없으면 print_progress
        total_processed += bytes_read;
        if (progress_cb) {
            progress_cb(total_processed, file_size, user_data);
        } else {
            print_progress(total_processed, file_size, "Encrypting");
        }
    }
    
    fclose(fin);
    
    if (!success) {
        fclose(fout);
        return 0;
    }
    
    fclose(fout);
    
    // 진행률 완료 표시
    if (progress_cb) {
        progress_cb(file_size, file_size, user_data);
    } else {
        print_progress(file_size, file_size, "Encrypting");
        printf("\nEncryption completed!\n");
    }
    
    return 1;
}

// Existing function (for CLI - calls internal function with NULL callback)
int encrypt_file(const char* input_path, const char* output_path,
                 int aes_key_bits, const char* password) {
    return encrypt_file_internal(input_path, output_path, aes_key_bits, password, NULL, NULL);
}

// New function (for GUI - supports progress callback)
int encrypt_file_with_progress(const char* input_path, const char* output_path,
                               int aes_key_bits, const char* password,
                               progress_callback_t progress_cb, void* user_data) {
    return encrypt_file_internal(input_path, output_path, aes_key_bits, password, progress_cb, user_data);
}

// Read AES key length from header (for verification before decryption)
int read_aes_key_length(const char* input_path) {
    FILE* fin = platform_fopen(input_path, "rb");
    if (!fin) {
        return 0;
    }
    
    EncFileHeader header;
    if (fread(&header, 1, sizeof(header), fin) != sizeof(header)) {
        fclose(fin);
        return 0;
    }
    
    fclose(fin);
    
    // 시그니처 검증
    if (memcmp(header.signature, ENC_SIGNATURE, 4) != 0) {
        return 0;
    }
    
    // Return actual key length from key length code
    if (header.key_length_code == 0x01) return 128;
    else if (header.key_length_code == 0x02) return 192;
    else if (header.key_length_code == 0x03) return 256;
    else return 0;
}

// Internal file decryption function (with progress callback support)
static int decrypt_file_internal(const char* input_path, const char* output_path,
                                  const char* password, char* final_output_path, size_t final_path_size,
                                  progress_callback_t progress_cb, void* user_data) {
    FILE* fin = platform_fopen(input_path, "rb");
    if (!fin) {
        if (!progress_cb) printf("Error: Cannot open file: %s\n", input_path);
        return 0;
    }
    
    // Read header
    EncFileHeader header;
    if (fread(&header, 1, sizeof(header), fin) != sizeof(header)) {
        fclose(fin);
        if (!progress_cb) printf("Error: Cannot read file header.\n");
        return 0;
    }
    
    // 시그니처 검증
    if (memcmp(header.signature, ENC_SIGNATURE, 4) != 0) {
        fclose(fin);
        if (!progress_cb) printf("Error: Invalid file format.\n");
        return 0;
    }
    
    // 파일 크기 확인
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    
    // HMAC is after header
    long hmac_position = sizeof(header);
    long ciphertext_size = file_size - sizeof(header) - 64; // Exclude header and HMAC
    
    if (ciphertext_size <= 0) {
        fclose(fin);
        if (!progress_cb) printf("Error: Invalid file size.\n");
        return 0;
    }
    
    // Read HMAC (position after header)
    fseek(fin, hmac_position, SEEK_SET);
    uint8_t stored_hmac[64];
    if (fread(stored_hmac, 1, 64, fin) != 64) {
        fclose(fin);
        if (!progress_cb) printf("Error: Cannot read HMAC.\n");
        return 0;
    }
    
    // Determine AES key length
    int aes_key_bits;
    if (header.key_length_code == 0x01) aes_key_bits = 128;
    else if (header.key_length_code == 0x02) aes_key_bits = 192;
    else if (header.key_length_code == 0x03) aes_key_bits = 256;
    else {
        fclose(fin);
        if (!progress_cb) printf("Error: Unsupported AES key length.\n");
        return 0;
    }
    
    // 키 도출
    uint8_t aes_key[32];
    uint8_t hmac_key[24];
    derive_keys(password, aes_key_bits, aes_key, hmac_key);
    
    // AES 컨텍스트 설정
    AES_CTX aes_ctx;
    if (AES_set_key(&aes_ctx, aes_key, aes_key_bits) != CRYPTO_SUCCESS) {
        fclose(fin);
        return 0;
    }
    
    // nonce_counter for CTR mode
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, header.nonce, 8);
    memset(nonce_counter + 8, 0, 8);
    
    if (!progress_cb) printf("Decrypting...\n");
    
    // Move to ciphertext position (after header + HMAC)
    fseek(fin, sizeof(header) + 64, SEEK_SET);
    
    // Store decrypted plaintext in temporary file (for HMAC verification)
    FILE* ftemp = tmpfile();
    if (!ftemp) {
        fclose(fin);
        printf("Error: Cannot create temporary file.\n");
        return 0;
    }
    
    // Read and decrypt ciphertext
    uint8_t buffer[FILE_CHUNK_SIZE];
    size_t bytes_read;
    long total_read = 0;
    int success = 1;
    
    while (total_read < ciphertext_size) {
        size_t to_read = (ciphertext_size - total_read < FILE_CHUNK_SIZE) ? 
                         (ciphertext_size - total_read) : FILE_CHUNK_SIZE;
        bytes_read = fread(buffer, 1, to_read, fin);
        if (bytes_read == 0) break;
        
        // Decrypt chunk (in-place)
        if (AES_CTR_crypt(&aes_ctx, buffer, bytes_read, buffer, nonce_counter) != CRYPTO_SUCCESS) {
            success = 0;
            break;
        }
        
        // Store decrypted plaintext in temporary file
        if (fwrite(buffer, 1, bytes_read, ftemp) != bytes_read) {
            success = 0;
            break;
        }
        
        total_read += bytes_read;
        
        // 진행률 업데이트 - 콜백이 있으면 콜백, 없으면 print_progress
        if (progress_cb) {
            // Decryption is considered 50% of total (HMAC verification is 50%)
            progress_cb(total_read / 2, ciphertext_size, user_data);
        } else {
            print_progress(total_read, ciphertext_size, "Decrypting");
        }
    }
    
    fclose(fin);
    
    if (!success) {
        fclose(ftemp);
        if (!progress_cb) printf("\nDecryption failed!\n");
        return 0;
    }
    
    if (!progress_cb) printf("\nDecryption completed! Verifying HMAC...\n");
    
    // HMAC verification: Generate HMAC from header + decrypted plaintext
    HMAC_SHA512_CTX hmac_ctx;
    hmac_sha512_init(&hmac_ctx, hmac_key, 24);
    hmac_sha512_update(&hmac_ctx, (uint8_t*)&header, sizeof(header));  // 헤더를 HMAC에 포함
    
    // Read decrypted plaintext from temporary file and update HMAC
    fseek(ftemp, 0, SEEK_SET);
    total_read = 0;
    
    while ((bytes_read = fread(buffer, 1, FILE_CHUNK_SIZE, ftemp)) > 0) {
        hmac_sha512_update(&hmac_ctx, buffer, bytes_read);
        total_read += bytes_read;
    }
    
    // HMAC 최종 계산
    uint8_t computed_hmac[64];
    hmac_sha512_final(&hmac_ctx, computed_hmac);
    
    // Verify HMAC
    if (memcmp(stored_hmac, computed_hmac, 64) != 0) {
        fclose(ftemp);
        if (!progress_cb) printf("Error: HMAC integrity verification failed. File may be corrupted or password is incorrect.\n");
        return 0;
    }
    
    if (!progress_cb) printf("HMAC verification succeeded! Integrity confirmed.\n");
    
    // Update progress (HMAC verification completed)
    if (progress_cb) {
        progress_cb(ciphertext_size / 2, ciphertext_size, user_data);
    }
    
    // Read original extension from header
    char format_ext[16] = {0};
    strncpy(format_ext, (const char*)header.format, 8);
    format_ext[8] = '\0';
    size_t ext_len = strlen(format_ext);
    
    // Add extension to output file path
    char actual_output_path[512];
    strncpy(actual_output_path, output_path, sizeof(actual_output_path) - 1);
    actual_output_path[sizeof(actual_output_path) - 1] = '\0';
    
    if (ext_len > 0) {
        // 출력 경로에 확장자가 없으면 추가
        char* last_dot = strrchr(actual_output_path, '.');
        char* last_slash = strrchr(actual_output_path, '/');
#ifdef _WIN32
        char* last_backslash = strrchr(actual_output_path, '\\');
        if (last_backslash && (!last_slash || last_backslash > last_slash)) {
            last_slash = last_backslash;
        }
#endif
        if (!last_dot || (last_slash && last_dot < last_slash)) {
            // Add extension if not present
            size_t path_len = strlen(actual_output_path);
            if (path_len + ext_len < sizeof(actual_output_path)) {
                strncpy(actual_output_path + path_len, format_ext, ext_len);
                actual_output_path[path_len + ext_len] = '\0';
            }
        }
    }
    
    // Return actual saved file path
    if (final_output_path && final_path_size > 0) {
        strncpy(final_output_path, actual_output_path, final_path_size - 1);
        final_output_path[final_path_size - 1] = '\0';
    }
    
    // 출력 파일 작성
    FILE* fout = platform_fopen(actual_output_path, "wb");
    if (!fout) {
        fclose(ftemp);
        return 0;
    }
    
    // Copy decrypted plaintext from temporary file to final output file
    fseek(ftemp, 0, SEEK_SET);
    total_read = 0;
    
    while ((bytes_read = fread(buffer, 1, FILE_CHUNK_SIZE, ftemp)) > 0) {
        if (fwrite(buffer, 1, bytes_read, fout) != bytes_read) {
            fclose(ftemp);
            fclose(fout);
            remove(actual_output_path);
            return 0;
        }
        total_read += bytes_read;
    }
    
    fclose(ftemp);
    fclose(fout);
    
    // 진행률 완료 표시
    if (progress_cb) {
        progress_cb(ciphertext_size, ciphertext_size, user_data);
    } else {
        printf("Decryption completed!\n");
    }
    
    return 1;
}

// Basic function (for CLI - called when progress callback is NULL)
int decrypt_file(const char* input_path, const char* output_path,
                 const char* password, char* final_output_path, size_t final_path_size) {
    return decrypt_file_internal(input_path, output_path, password, final_output_path, final_path_size, NULL, NULL);
}

// Function for GUI (with progress callback support)
int decrypt_file_with_progress(const char* input_path, const char* output_path,
                               const char* password, char* final_output_path, size_t final_path_size,
                               progress_callback_t progress_cb, void* user_data) {
    return decrypt_file_internal(input_path, output_path, password, final_output_path, final_path_size, progress_cb, user_data);
}

#ifndef BUILD_GUI
int main(void) {
    // Check if OpenSSL is enabled
#ifdef USE_OPENSSL
    printf("OpenSSL enabled\n");
#else
    printf("OpenSSL disabled\n");
#endif
    
    // Initialize seed (only once at program start)
    srand((unsigned int)time(NULL));
    
    int service;
    char file_path[512];
    char password[32];
    int aes_choice;
    int aes_key_bits;
    
    printf("=======================================\n");
    printf("    File Encryption/Decryption Program \n");
    printf("=======================================\n\n");
    
    // Service selection
    printf("Enter service number:\n");
    printf("1. File Encryption\n");
    printf("2. File Decryption\n");
    printf("Choice: ");
    
    if (scanf("%d", &service) != 1 || (service != 1 && service != 2)) {
        printf("Error: Invalid input.\n");
        return 1;
    }
    
    if (service == 1) {
        // 암호화
        printf("\nEnter file path to encrypt: ");
        if (scanf("%511s", file_path) != 1) {
            printf("Error: Cannot read file path.\n");
            return 1;
        }
        
        printf("\nSelect AES for encryption:\n");
        printf("1. AES-128\n");
        printf("2. AES-192\n");
        printf("3. AES-256\n");
        printf("Choice: ");
        
        if (scanf("%d", &aes_choice) != 1 || aes_choice < 1 || aes_choice > 3) {
            printf("Error: Invalid choice.\n");
            return 1;
        }
        
        aes_key_bits = (aes_choice == 1) ? 128 : (aes_choice == 2) ? 192 : 256;
        printf("\nStarting file encryption with AES-%d-CTR.\n", aes_key_bits);
        
        printf("Enter password (alphanumeric, case-sensitive, max 10 chars): ");
        if (scanf("%31s", password) != 1) {
            printf("Error: Cannot read password.\n");
            return 1;
        }
        
        if (!validate_password(password)) {
            printf("Error: Password must be alphanumeric (case-sensitive) with maximum 10 characters.\n");
            return 1;
        }
        
        // 저장할 경로 입력
        char save_path[512];
        printf("Enter path to save encrypted file: ");
        if (scanf("%511s", save_path) != 1) {
            printf("Error: Cannot read save path.\n");
            return 1;
        }
        
        // 파일 이름 입력
        char file_name[256];
        printf("Enter encrypted file name (.enc extension will be added automatically): ");
        if (scanf("%255s", file_name) != 1) {
            printf("Error: Cannot read file name.\n");
            return 1;
        }
        
        // 최종 출력 경로 생성 (경로 + 파일명 + .enc)
        char output_path[512];
        size_t path_len = strlen(save_path);
        // 경로 끝에 구분자가 없으면 추가
        if (path_len > 0 && save_path[path_len - 1] != '/' && save_path[path_len - 1] != '\\') {
#ifdef _WIN32
            snprintf(output_path, sizeof(output_path), "%s\\%s.enc", save_path, file_name);
#else
            snprintf(output_path, sizeof(output_path), "%s/%s.enc", save_path, file_name);
#endif
        } else {
            snprintf(output_path, sizeof(output_path), "%s%s.enc", save_path, file_name);
        }
        
        if (encrypt_file(file_path, output_path, aes_key_bits, password)) {
            printf("File encryption and HMAC generation succeeded.\n");
            printf("Encrypted file: %s\n", output_path);
        } else {
            printf("Error: File encryption failed.\n");
            return 1;
        }
        
    } else if (service == 2) {
        // 복호화
        printf("\nEnter file path to decrypt: ");
        if (scanf("%511s", file_path) != 1) {
            printf("Error: Cannot read file path.\n");
            return 1;
        }
        
        // 헤더에서 AES 키 길이 읽기
        int aes_key_bits = read_aes_key_length(file_path);
        if (aes_key_bits == 0) {
            printf("Error: Cannot read encrypted file or invalid format.\n");
            return 1;
        }
        
        printf("\nStarting file decryption with AES-%d-CTR.\n", aes_key_bits);
        printf("Enter password used for encryption: ");
        if (scanf("%31s", password) != 1) {
            printf("Error: Cannot read password.\n");
            return 1;
        }
        
        // 저장할 경로 입력
        char save_path[512];
        printf("Enter path to save decrypted file (excluding filename): ");
        if (scanf("%511s", save_path) != 1) {
            printf("Error: Cannot read save path.\n");
            return 1;
        }
        
        // 파일 이름 입력 (확장자는 자동으로 추가됨)
        char file_name[256];
        printf("Enter decrypted file name (extension will be added automatically): ");
        if (scanf("%255s", file_name) != 1) {
            printf("Error: Cannot read file name.\n");
            return 1;
        }
        
        // 최종 출력 경로 생성 (경로 + 파일명, 확장자는 decrypt_file에서 추가)
        char output_path[512];
        size_t path_len = strlen(save_path);
        // 경로 끝에 구분자가 없으면 추가
        if (path_len > 0 && save_path[path_len - 1] != '/' && save_path[path_len - 1] != '\\') {
#ifdef _WIN32
            snprintf(output_path, sizeof(output_path), "%s\\%s", save_path, file_name);
#else
            snprintf(output_path, sizeof(output_path), "%s/%s", save_path, file_name);
#endif
        } else {
            snprintf(output_path, sizeof(output_path), "%s%s", save_path, file_name);
        }
        
        char actual_output_path[512];
        if (decrypt_file(file_path, output_path, password, actual_output_path, sizeof(actual_output_path))) {
            printf("Integrity verified. File decryption succeeded.\n");
            printf("Decrypted file: %s\n", actual_output_path);
        } else {
            printf("Error: File decryption failed.\n");
            return 1;
        }
    }
    
    return 0;
}
#endif // BUILD_GUI