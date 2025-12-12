#include "password_utils.h"
#include <string.h>

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

