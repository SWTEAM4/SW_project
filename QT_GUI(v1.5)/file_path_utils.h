#ifndef FILE_PATH_UTILS_H
#define FILE_PATH_UTILS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 파일 경로에서 확장자 추출 (예: "file.txt" -> ".txt")
// 확장자가 없으면 빈 문자열 반환
void extract_extension(const char* file_path, char* ext, size_t ext_size);

// 출력 파일 경로 생성 (경로 + 파일명 + 확장자)
// save_path 끝에 구분자가 없으면 자동으로 추가
// extension이 NULL이면 확장자를 추가하지 않음
void build_output_path(char* output_path, size_t output_size,
                       const char* save_path, const char* file_name,
                       const char* extension);

#ifdef __cplusplus
}
#endif

#endif // FILE_PATH_UTILS_H

