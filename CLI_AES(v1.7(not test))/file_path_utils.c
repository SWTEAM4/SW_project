#define _CRT_SECURE_NO_WARNINGS
#include "file_path_utils.h"
#include "platform_utils.h"
#include <string.h>
#include <stdio.h>

// 파일 경로에서 확장자 추출 (예: "file.txt" -> ".txt")
// 확장자가 없으면 빈 문자열 반환
void extract_extension(const char* file_path, char* ext, size_t ext_size) {
    if (!file_path || !ext || ext_size == 0) {
        if (ext && ext_size > 0) ext[0] = '\0';
        return;
    }
    
    const char* last_dot = strrchr(file_path, '.');
    const char* last_slash = platform_find_last_separator(file_path);
    
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

// 출력 파일 경로 생성 (경로 + 파일명 + 확장자)
// save_path 끝에 구분자가 없으면 자동으로 추가
// extension이 NULL이면 확장자를 추가하지 않음
void build_output_path(char* output_path, size_t output_size,
                       const char* save_path, const char* file_name,
                       const char* extension) {
    if (!output_path || output_size == 0 || !save_path || !file_name) {
        if (output_path && output_size > 0) {
            output_path[0] = '\0';
        }
        return;
    }
    
    size_t path_len = strlen(save_path);
    
    // 경로 끝에 구분자가 없으면 추가
    if (path_len > 0 && save_path[path_len - 1] != '/' && save_path[path_len - 1] != '\\') {
#ifdef _WIN32
        if (extension) {
            int written = snprintf(output_path, output_size, "%s\\%s%s", save_path, file_name, extension);
            if (written < 0 || (size_t)written >= output_size) {
                output_path[0] = '\0';
                return;
            }
        } else {
            int written = snprintf(output_path, output_size, "%s\\%s", save_path, file_name);
            if (written < 0 || (size_t)written >= output_size) {
                output_path[0] = '\0';
                return;
            }
        }
#else
        if (extension) {
            int written = snprintf(output_path, output_size, "%s/%s%s", save_path, file_name, extension);
            if (written < 0 || (size_t)written >= output_size) {
                output_path[0] = '\0';
                return;
            }
        } else {
            int written = snprintf(output_path, output_size, "%s/%s", save_path, file_name);
            if (written < 0 || (size_t)written >= output_size) {
                output_path[0] = '\0';
                return;
            }
        }
#endif
    } else {
        // 경로 끝에 구분자가 이미 있음
        if (extension) {
            int written = snprintf(output_path, output_size, "%s%s%s", save_path, file_name, extension);
            if (written < 0 || (size_t)written >= output_size) {
                output_path[0] = '\0';
                return;
            }
        } else {
            int written = snprintf(output_path, output_size, "%s%s", save_path, file_name);
            if (written < 0 || (size_t)written >= output_size) {
                output_path[0] = '\0';
                return;
            }
        }
    }
}

