#define _CRT_SECURE_NO_WARNINGS
#include "platform_utils.h"
#include <string.h>
#include <stdlib.h>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
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
#endif

