#ifndef ERROR_UTILS_H
#define ERROR_UTILS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Formats an error message into dest. When include_system_error is non-zero,
 * platform-specific error information (GetLastError / errno) is appended.
 */
void format_error_message(char *dest, size_t dest_size,
                          const char *context, int include_system_error);

#ifdef __cplusplus
}
#endif

#endif // ERROR_UTILS_H


