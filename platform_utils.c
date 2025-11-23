#define _CRT_SECURE_NO_WARNINGS
#include "platform_utils.h"
#include <string.h>
#include <stdlib.h>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

// Windows temporary file path storage (for cleanup)
static wchar_t g_temp_file_path[MAX_PATH] = {0};
// Windows implementation
FILE* platform_fopen(const char* path, const char* mode) {
    wchar_t wpath[512];
    wchar_t wmode[16];
    
    // Convert UTF-8 path to wide char
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 512);
    
    // Convert mode string
    MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 16);
    
    return _wfopen(wpath, wmode);
}

int platform_path_to_utf8(const char* input_path, char* output_path, size_t output_size) {
    // On Windows, assume input is already UTF-8 or ANSI
    // Convert from ANSI to UTF-8 if needed
    wchar_t wpath[512];
    int len = MultiByteToWideChar(CP_ACP, 0, input_path, -1, wpath, 512);
    if (len <= 0) {
        strncpy(output_path, input_path, output_size - 1);
        output_path[output_size - 1] = '\0';
        return 0;
    }
    
    int result = WideCharToMultiByte(CP_UTF8, 0, wpath, -1, output_path, (int)output_size, NULL, NULL);
    return (result > 0) ? 0 : -1;
}

// Windows temporary file creation
FILE* platform_tmpfile(void) {
    wchar_t temp_path[MAX_PATH];
    
    // Clear previous temp file path
    g_temp_file_path[0] = L'\0';
    
    // Get temporary directory
    DWORD path_len = GetTempPathW(MAX_PATH, temp_path);
    if (path_len == 0 || path_len >= MAX_PATH) {
        return NULL;
    }
    
    // Generate unique temporary file name
    UINT unique = GetTempFileNameW(temp_path, L"ENC", 0, g_temp_file_path);
    if (unique == 0) {
        return NULL;
    }
    
    // Open file in binary read/write mode
    return _wfopen(g_temp_file_path, L"w+b");
}

// Windows temporary file cleanup (call after fclose)
void platform_tmpfile_cleanup(void) {
    if (g_temp_file_path[0] != L'\0') {
        DeleteFileW(g_temp_file_path);
        g_temp_file_path[0] = L'\0';
    }
}

#elif defined(PLATFORM_MAC)
// macOS implementation
FILE* platform_fopen(const char* path, const char* mode) {
    // macOS uses UTF-8 by default, so we can use standard fopen
    return fopen(path, mode);
}

int platform_path_to_utf8(const char* input_path, char* output_path, size_t output_size) {
    // macOS uses UTF-8 by default
    strncpy(output_path, input_path, output_size - 1);
    output_path[output_size - 1] = '\0';
    return 0;
}

// macOS temporary file creation
FILE* platform_tmpfile(void) {
    // macOS uses standard tmpfile() which auto-deletes
    return tmpfile();
}

// macOS temporary file cleanup (no-op, tmpfile() auto-deletes)
void platform_tmpfile_cleanup(void) {
    // No cleanup needed, tmpfile() auto-deletes
}

#else
// Linux/Unix implementation
FILE* platform_fopen(const char* path, const char* mode) {
    return fopen(path, mode);
}

int platform_path_to_utf8(const char* input_path, char* output_path, size_t output_size) {
    strncpy(output_path, input_path, output_size - 1);
    output_path[output_size - 1] = '\0';
    return 0;
}

// Linux/Unix temporary file creation
FILE* platform_tmpfile(void) {
    // Linux/Unix uses standard tmpfile() which auto-deletes
    return tmpfile();
}

// Linux/Unix temporary file cleanup (no-op, tmpfile() auto-deletes)
void platform_tmpfile_cleanup(void) {
    // No cleanup needed, tmpfile() auto-deletes
}
#endif

