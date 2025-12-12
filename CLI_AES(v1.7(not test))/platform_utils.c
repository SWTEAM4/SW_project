#define _CRT_SECURE_NO_WARNINGS
#include "platform_utils.h"
#include <string.h>
#include <stdlib.h>

#ifdef PLATFORM_WINDOWS
#include <io.h>
#elif defined(PLATFORM_MAC) || defined(PLATFORM_LINUX)
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#endif

// Cross-platform file deletion implementation
int platform_delete_file(const char* file_path) {
    if (!file_path) return 0;
    
#ifdef PLATFORM_WINDOWS
    return (DeleteFileA(file_path) != 0) ? 1 : 0;
#else
    return (unlink(file_path) == 0) ? 1 : 0;
#endif
}

// Find last path separator (both / and \) implementation
const char* platform_find_last_separator(const char* path) {
    if (!path) return NULL;
    
    const char* last_slash = strrchr(path, '/');
#ifdef _WIN32
    const char* last_backslash = strrchr(path, '\\');
    if (last_backslash && (!last_slash || last_backslash > last_slash)) {
        return last_backslash;
    }
#endif
    return last_slash;
}

// Cross-platform directory existence check
int platform_directory_exists(const char* dir_path) {
    if (!dir_path) return 0;
    
#ifdef PLATFORM_WINDOWS
    DWORD dwAttrib = GetFileAttributesA(dir_path);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) ? 1 : 0;
#else
    // Unix/Linux/macOS: stat() 사용
    struct stat st;
    if (stat(dir_path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 1 : 0;
    }
    return 0;
#endif
}

// Cross-platform file existence check
int platform_file_exists(const char* file_path) {
    if (!file_path) return 0;
    
#ifdef PLATFORM_WINDOWS
    DWORD dwAttrib = GetFileAttributesA(file_path);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
            !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) ? 1 : 0;
#else
    // Unix/Linux/macOS: fopen()으로 확인
    FILE* f = fopen(file_path, "r");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
#endif
}

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

FILE* platform_create_temp_file(char* temp_path, size_t temp_path_size) {
    char temp_dir[MAX_PATH];
    char temp_file[MAX_PATH];
    
    // Windows 임시 디렉토리 경로 가져오기
    DWORD path_len = GetTempPathA(MAX_PATH, temp_dir);
    if (path_len == 0 || path_len >= MAX_PATH) {
        return NULL;
    }
    
    // 임시 파일명 생성
    UINT unique = GetTempFileNameA(temp_dir, "decrypt", 0, temp_file);
    if (unique == 0) {
        return NULL;
    }
    
    // 경로 복사
    if (temp_path && temp_path_size > 0) {
        strncpy(temp_path, temp_file, temp_path_size - 1);
        temp_path[temp_path_size - 1] = '\0';
    }
    
    // 파일 열기 (읽기/쓰기, 바이너리)
    return platform_fopen(temp_file, "w+b");
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

FILE* platform_create_temp_file(char* temp_path, size_t temp_path_size) {
    char template[] = "/tmp/decrypt_XXXXXX";
    int fd = mkstemp(template);
    if (fd == -1) {
        return NULL;
    }
    
    // 경로 복사
    if (temp_path && temp_path_size > 0) {
        strncpy(temp_path, template, temp_path_size - 1);
        temp_path[temp_path_size - 1] = '\0';
    }
    
    // 파일 디스크립터를 FILE*로 변환
    FILE* f = fdopen(fd, "w+b");
    if (!f) {
        close(fd);
        unlink(template);
        return NULL;
    }
    
    return f;
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

FILE* platform_create_temp_file(char* temp_path, size_t temp_path_size) {
    char template[] = "/tmp/decrypt_XXXXXX";
    int fd = mkstemp(template);
    if (fd == -1) {
        return NULL;
    }
    
    // 경로 복사
    if (temp_path && temp_path_size > 0) {
        strncpy(temp_path, template, temp_path_size - 1);
        temp_path[temp_path_size - 1] = '\0';
    }
    
    // 파일 디스크립터를 FILE*로 변환
    FILE* f = fdopen(fd, "w+b");
    if (!f) {
        close(fd);
        unlink(template);
        return NULL;
    }
    
    return f;
}
#endif

