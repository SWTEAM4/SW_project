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

// Cross-platform file deletion
// Returns 1 on success, 0 on failure
int platform_delete_file(const char* file_path);

// Find last path separator (both / and \)
// Returns pointer to the last separator, or NULL if not found
const char* platform_find_last_separator(const char* path);

// Check if directory exists
// Returns 1 if directory exists, 0 if not
int platform_directory_exists(const char* dir_path);

// Check if file exists
// Returns 1 if file exists, 0 if not
int platform_file_exists(const char* file_path);

#ifdef __cplusplus
}
#endif

#endif // PLATFORM_UTILS_H

