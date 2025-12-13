#include "error_utils.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#include <windows.h>
#endif

void format_error_message(char *dest, size_t dest_size,
                          const char *context, int include_system_error)
{
    if (!dest || dest_size == 0 || !context) {
        return;
    }

#ifdef _WIN32
    if (include_system_error) {
        DWORD err = GetLastError();
        WCHAR wide_msg[256] = {0};
        int chars = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            err,
            0,
            wide_msg,
            (DWORD)(sizeof(wide_msg) / sizeof(WCHAR)),
            NULL);

        char utf8_msg[512] = {0};
        if (chars > 0) {
            WideCharToMultiByte(CP_UTF8, 0, wide_msg, -1,
                                utf8_msg, sizeof(utf8_msg), NULL, NULL);
        }

        if (utf8_msg[0] != '\0') {
            snprintf(dest, dest_size, "%s (error %lu: %s)",
                     context, (unsigned long)err, utf8_msg);
        } else {
            snprintf(dest, dest_size, "%s (error %lu)",
                     context, (unsigned long)err);
        }
    } else {
        snprintf(dest, dest_size, "%s", context);
    }
#else
    if (include_system_error) {
        snprintf(dest, dest_size, "%s (%s)", context, strerror(errno));
    } else {
        snprintf(dest, dest_size, "%s", context);
    }
#endif
}


