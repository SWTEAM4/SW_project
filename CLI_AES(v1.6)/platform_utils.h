#ifndef PLATFORM_UTILS_H
#define PLATFORM_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

// Platform detection
#ifdef _WIN32
    #define PLATFORM_WINDOWS 1
    #include <windows.h>
    #ifndef CP_UTF8
    #define CP_UTF8 65001
    #endif
#elif defined(__APPLE__)
    #define PLATFORM_MAC 1
    #include <CoreFoundation/CoreFoundation.h>
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
#endif

// Cross-platform file operations
FILE* platform_fopen(const char* path, const char* mode);
int platform_path_to_utf8(const char* input_path, char* output_path, size_t output_size);

// Cross-platform temporary file creation
// Returns FILE* on success, NULL on failure. Caller must close the file.
// temp_path will contain the path to the temporary file (can be NULL if path is not needed)
FILE* platform_create_temp_file(char* temp_path, size_t temp_path_size);

#ifdef __cplusplus
}
#endif

#endif // PLATFORM_UTILS_H

