#ifndef PASSWORD_UTILS_H
#define PASSWORD_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

// 패스워드 검증 (영문+숫자, 대소문자, 최대 10자)
int validate_password(const char* password);

#ifdef __cplusplus
}
#endif

#endif // PASSWORD_UTILS_H

