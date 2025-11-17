#define _CRT_SECURE_NO_WARNINGS

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <io.h>
#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
#elif defined(PLATFORM_MAC)
// Mac GUI will be implemented separately or using cross-platform library
// For now, this file is Windows-only
#error "Mac GUI not implemented. Use gui_mac.m for macOS."
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file_crypto.h"
#include "platform_utils.h"

#ifndef _MAX_DRIVE
#define _MAX_DRIVE 3
#define _MAX_DIR 256
#define _MAX_FNAME 256
#define _MAX_EXT 256
#endif

// 리소스 ID 정의
#define IDC_MAIN_WINDOW           1000
#define IDC_DROP_AREA             1001
#define IDC_PASSWORD_EDIT         1002
#define IDC_AES_COMBO             1003
#define IDC_ENCRYPT_BUTTON        1004
#define IDC_DECRYPT_BUTTON        1005
#define IDC_STATUS_TEXT           1006
#define IDC_FILE_LIST             1007
#define IDC_FILE_SELECT_BUTTON    1008
#define IDC_FILE_DELETE_BUTTON    1009

#ifdef PLATFORM_WINDOWS
// Global variables
static HWND g_hMainWnd = NULL;
static HWND g_hDropArea = NULL;
static HWND g_hPasswordEdit = NULL;
static HWND g_hAESCombo = NULL;
static HWND g_hStatusText = NULL;
static HWND g_hFileList = NULL;
static HWND g_hFileSelectButton = NULL;
static HWND g_hFileDeleteButton = NULL;
static char g_droppedFiles[10][512];  // Stores up to 10 file paths
static int g_fileCount = 0;

// Function declarations
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK DropAreaProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void CreateControls(HWND hwnd);
void UpdateStatus(const wchar_t* message);
void ProcessDroppedFiles(HDROP hDrop);
void ClearFileList(void);
void AddFileToList(const char* filepath);
int GetSelectedAESBits(void);
void EncryptFiles(void);
void DecryptFiles(void);
void GetOutputPath(const char* input_path, char* output_path, size_t output_size, int is_encrypt);
void AppendSuffixBeforeExtension(char* path, size_t path_size, const char* suffix);
void SelectFilesWithDialog(void);
void AddFileFromWidePath(const wchar_t* wide_path);
void DeleteSelectedFile(void);

// Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"FileCryptoWindowClass";
    
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    if (!RegisterClass(&wc)) {
        MessageBox(NULL, L"\uC708\uB3C4\uC6B0 \uD074\uB798\uC2A4 \uB4F1\uB85D \uC2E4\uD328", L"\uC624\uB958", MB_OK | MB_ICONERROR);
        return 0;
    }
    
    g_hMainWnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"\uD30C\uC77C \uC554\uD638\uD654/\uBCF5\uD638\uD654 \uD504\uB85C\uADF8\uB7A8",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        600, 500,
        NULL, NULL, hInstance, NULL
    );
    
    if (g_hMainWnd == NULL) {
        return 0;
    }
    
    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);
    
    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}

// 윈도우 프로시저
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            CreateControls(hwnd);
            return 0;
            
        case WM_COMMAND:
            if (LOWORD(wParam) == IDC_ENCRYPT_BUTTON) {
                EncryptFiles();
            } else if (LOWORD(wParam) == IDC_DECRYPT_BUTTON) {
                DecryptFiles();
            } else if (LOWORD(wParam) == IDC_FILE_SELECT_BUTTON) {
                SelectFilesWithDialog();
            } else if (LOWORD(wParam) == IDC_FILE_DELETE_BUTTON) {
                DeleteSelectedFile();
            }
            return 0;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// 드롭 영역 프로시저
LRESULT CALLBACK DropAreaProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            // Draw background
            FillRect(hdc, &rect, (HBRUSH)(COLOR_WINDOW + 1));
            
            // Draw border
            HPEN hPen = CreatePen(PS_DASH, 2, RGB(100, 100, 100));
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            Rectangle(hdc, rect.left + 5, rect.top + 5, rect.right - 5, rect.bottom - 5);
            SelectObject(hdc, hOldPen);
            DeleteObject(hPen);
            
            // Draw text
            SetTextColor(hdc, RGB(100, 100, 100));
            SetBkMode(hdc, TRANSPARENT);
            DrawText(hdc, L"\uD30C\uC77C\uC744 \uC5EC\uAE30\uC5D0 \uB4DC\uB798\uADF8 \uC564 \uB4DC\uB86D\uD558\uC138\uC694", -1, &rect, 
                     DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            ProcessDroppedFiles(hDrop);
            DragFinish(hDrop);
            return 0;
        }
    }
    
    #ifdef _WIN64
        return CallWindowProc((WNDPROC)GetWindowLongPtr(hwnd, GWLP_USERDATA), hwnd, uMsg, wParam, lParam);
    #else
        return CallWindowProc((WNDPROC)GetWindowLong(hwnd, GWL_USERDATA), hwnd, uMsg, wParam, lParam);
    #endif
}

// 컨트롤 생성
void CreateControls(HWND hwnd) {
    // Drop area
    g_hDropArea = CreateWindow(
        L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_NOTIFY,
        10, 10, 560, 120,
        hwnd, (HMENU)IDC_DROP_AREA, NULL, NULL
    );
    
    // Apply subclassing to the drop area
    #ifdef _WIN64
        SetWindowLongPtr(g_hDropArea, GWLP_USERDATA, (LONG_PTR)GetWindowLongPtr(g_hDropArea, GWLP_WNDPROC));
        SetWindowLongPtr(g_hDropArea, GWLP_WNDPROC, (LONG_PTR)DropAreaProc);
    #else
        SetWindowLong(g_hDropArea, GWL_USERDATA, (LONG)GetWindowLong(g_hDropArea, GWL_WNDPROC));
        SetWindowLong(g_hDropArea, GWL_WNDPROC, (LONG)DropAreaProc);
    #endif
    DragAcceptFiles(g_hDropArea, TRUE);
    
    // File list label with decrypt notice
    CreateWindow(L"STATIC", L"\uC120\uD0DD\uB41C \uD30C\uC77C (\uBCF5\uD638\uD654\uC2DC .enc \uD615\uC2DD \uD544\uC694):", WS_CHILD | WS_VISIBLE,
                 10, 140, 300, 20, hwnd, NULL, NULL, NULL);
    
    g_hFileList = CreateWindow(
        L"LISTBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER,
        10, 165, 560, 100,
        hwnd, (HMENU)IDC_FILE_LIST, NULL, NULL
    );
    
    // Password input
    CreateWindow(L"STATIC", L"\uD328\uC2A4\uC6CC\uB4DC (\uC601\uBB38+\uC22B\uC790, \uCD5C\uB300 10\uC790):", WS_CHILD | WS_VISIBLE,
                 10, 275, 250, 20, hwnd, NULL, NULL, NULL);
    
    g_hPasswordEdit = CreateWindow(
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
        10, 300, 250, 25,
        hwnd, (HMENU)IDC_PASSWORD_EDIT, NULL, NULL
    );
    
    // AES selection
    CreateWindow(L"STATIC", L"AES \uD0A4 \uAE38\uC774 (\uC554\uD638\uD654\uC6A9):", WS_CHILD | WS_VISIBLE,
                 280, 275, 200, 20, hwnd, NULL, NULL, NULL);
    
    g_hAESCombo = CreateWindow(
        L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        280, 300, 150, 200,
        hwnd, (HMENU)IDC_AES_COMBO, NULL, NULL
    );
    
    // Populate AES options
    SendMessage(g_hAESCombo, CB_ADDSTRING, 0, (LPARAM)L"AES-128");
    SendMessage(g_hAESCombo, CB_ADDSTRING, 0, (LPARAM)L"AES-192");
    SendMessage(g_hAESCombo, CB_ADDSTRING, 0, (LPARAM)L"AES-256");
    SendMessage(g_hAESCombo, CB_SETCURSEL, 0, 0);  // 기본값: AES-128
    
    // Encrypt button
    CreateWindow(
        L"BUTTON", L"\uC554\uD638\uD654",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        450, 300, 120, 30,
        hwnd, (HMENU)IDC_ENCRYPT_BUTTON, NULL, NULL
    );
    
    // Decrypt button
    CreateWindow(
        L"BUTTON", L"\uBCF5\uD638\uD654",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        450, 335, 120, 30,
        hwnd, (HMENU)IDC_DECRYPT_BUTTON, NULL, NULL
    );

    // File selection button
    g_hFileSelectButton = CreateWindow(
        L"BUTTON", L"\uD30C\uC77C \uC120\uD0DD",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        450, 270, 120, 25,
        hwnd, (HMENU)IDC_FILE_SELECT_BUTTON, NULL, NULL
    );
    
    // File delete button (top right of file list)
    g_hFileDeleteButton = CreateWindow(
        L"BUTTON", L"\uD30C\uC77C \uC0AD\uC81C",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        450, 140, 120, 25,
        hwnd, (HMENU)IDC_FILE_DELETE_BUTTON, NULL, NULL
    );
    
    // Status text
    wchar_t exe_path[MAX_PATH];
    GetModuleFileNameW(NULL, exe_path, MAX_PATH);
    wchar_t initial_status[512];
    swprintf(initial_status, 512, L"\uD30C\uC77C\uC744 \uB4DC\uB798\uADF8 \uC564 \uB4DC\uB86D\uD558\uC5EC \uC2DC\uC791\uD558\uC138\uC694.\n\n\uC2E4\uD589 \uACBD\uB85C: %s", exe_path);
    
    g_hStatusText = CreateWindow(
        L"STATIC", initial_status,
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 380, 560, 80,
        hwnd, (HMENU)IDC_STATUS_TEXT, NULL, NULL
    );
}

// Update status text (preserves executable path)
void UpdateStatus(const wchar_t* message) {
    if (g_hStatusText) {
        wchar_t exe_path[MAX_PATH];
        GetModuleFileNameW(NULL, exe_path, MAX_PATH);
        wchar_t full_message[512];
        swprintf(full_message, 512, L"%s\n\n\uC2E4\uD589 \uACBD\uB85C: %s", message, exe_path);
        SetWindowText(g_hStatusText, full_message);
    }
}

// Handle dropped files
void ProcessDroppedFiles(HDROP hDrop) {
    ClearFileList();
    
    UINT fileCount = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, 0);
    
    if (fileCount > 10) {
        MessageBox(g_hMainWnd, L"\uD30C\uC77C\uC740 \uCD5C\uB300 10\uAC1C\uB9CC \uC120\uD0DD\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.", L"\uC624\uB958", MB_OK | MB_ICONWARNING);
        UpdateStatus(L"\uC624\uB958: \uD30C\uC77C\uC740 \uCD5C\uB300 10\uAC1C\uB9CC \uC120\uD0DD\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.");
        return;
    }
    
    g_fileCount = fileCount;
    
    for (UINT i = 0; i < g_fileCount; i++) {
        wchar_t wfilepath[512];
        DragQueryFileW(hDrop, i, wfilepath, 512);
        
        char utf8_path[512];
        WideCharToMultiByte(CP_UTF8, 0, wfilepath, -1, utf8_path, sizeof(utf8_path), NULL, NULL);
        
        strncpy(g_droppedFiles[i], utf8_path, sizeof(g_droppedFiles[i]) - 1);
        g_droppedFiles[i][sizeof(g_droppedFiles[i]) - 1] = '\0';
        AddFileToList(utf8_path);
    }
    
    wchar_t status[256];
    swprintf(status, 256, L"%d\uAC1C\uC758 \uD30C\uC77C\uC774 \uC120\uD0DD\uB418\uC5C8\uC2B5\uB2C8\uB2E4.", g_fileCount);
    UpdateStatus(status);
}

// Reset file list
void ClearFileList(void) {
    if (g_hFileList) {
        SendMessage(g_hFileList, LB_RESETCONTENT, 0, 0);
    }
    g_fileCount = 0;
}

// Add file name to the list box
void AddFileToList(const char* filepath) {
    if (g_hFileList) {
        const char* filename;
        int len = 0;
        wchar_t* wfilename;

        // Extract filename only
        filename = strrchr(filepath, '\\');
        if (!filename) filename = strrchr(filepath, '/');
        if (!filename) filename = filepath;
        else filename++;
        
        // Convert UTF-8 to UTF-16
        len = MultiByteToWideChar(CP_UTF8, 0, filename, -1, NULL, 0);
        wfilename = (wchar_t*)malloc(len * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, filename, -1, wfilename, len);
        
        SendMessage(g_hFileList, LB_ADDSTRING, 0, (LPARAM)wfilename);
        free(wfilename);
    }
}

// Retrieve the AES key length selected in the combo box
int GetSelectedAESBits(void) {
    int sel = (int)SendMessage(g_hAESCombo, CB_GETCURSEL, 0, 0);
    if (sel == 0) return 128;
    else if (sel == 1) return 192;
    else if (sel == 2) return 256;
    return 128;
}

// Build output file path
void GetOutputPath(const char* input_path, char* output_path, size_t output_size, int is_encrypt) {
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];
    
    _splitpath_s(input_path, drive, _MAX_DRIVE, dir, _MAX_DIR, fname, _MAX_FNAME, ext, _MAX_EXT);
    
    if (is_encrypt) {
        // 암호화: .enc 확장자 추가
        _snprintf_s(output_path, output_size, _TRUNCATE, "%s%s%s.enc", drive, dir, fname);
    } else {
        // 복호화: .enc 제거 (확장자는 decrypt_file에서 자동 추가됨)
        _snprintf_s(output_path, output_size, _TRUNCATE, "%s%s%s", drive, dir, fname);
    }
}

// Insert suffix before the extension in a path
void AppendSuffixBeforeExtension(char* path, size_t path_size, const char* suffix) {
    if (!path || !suffix || path_size == 0) {
        return;
    }

    char buffer[512];
    strncpy(buffer, path, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char* last_dot = strrchr(buffer, '.');
    char* last_slash = strrchr(buffer, '/');
#ifdef _WIN32
    char* last_backslash = strrchr(buffer, '\\');
    if (last_backslash && (!last_slash || last_backslash > last_slash)) {
        last_slash = last_backslash;
    }
#endif

    size_t suffix_len = strlen(suffix);
    if (last_dot && (!last_slash || last_dot > last_slash)) {
        size_t base_len = (size_t)(last_dot - buffer);
        size_t ext_len = strlen(last_dot);
        if (base_len + suffix_len + ext_len >= sizeof(buffer)) {
            return;
        }
        memmove(buffer + base_len + suffix_len, last_dot, ext_len + 1);
        memcpy(buffer + base_len, suffix, suffix_len);
    } else {
        size_t len = strlen(buffer);
        if (len + suffix_len >= sizeof(buffer)) {
            return;
        }
        strcat(buffer, suffix);
    }

    strncpy(path, buffer, path_size - 1);
    path[path_size - 1] = '\0';
}

// Add a wide-character path to the internal UTF-8 list
void AddFileFromWidePath(const wchar_t* wide_path) {
    if (!wide_path || g_fileCount >= 10) {
        return;
    }

    char utf8_path[512];
    int converted = WideCharToMultiByte(CP_UTF8, 0, wide_path, -1, utf8_path, sizeof(utf8_path), NULL, NULL);
    if (converted <= 0) {
        return;
    }

    strncpy(g_droppedFiles[g_fileCount], utf8_path, sizeof(g_droppedFiles[g_fileCount]) - 1);
    g_droppedFiles[g_fileCount][sizeof(g_droppedFiles[g_fileCount]) - 1] = '\0';
    AddFileToList(utf8_path);
    g_fileCount++;
}

// Show the file selection dialog
void SelectFilesWithDialog(void) {
    wchar_t file_buffer[4096] = {0};

    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = L"\uBAA8\uB4E0 \uD30C\uC77C (*.*)\0*.*\0";
    ofn.lpstrFile = file_buffer;
    ofn.nMaxFile = (DWORD)(sizeof(file_buffer) / sizeof(wchar_t));
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_ALLOWMULTISELECT;

    if (!GetOpenFileName(&ofn)) {
        return;
    }

    // Don't clear existing files, just add new ones

    wchar_t* current = file_buffer;
    wchar_t directory[MAX_PATH];
    size_t first_len = wcslen(current);

    if (current[first_len + 1] == L'\0') {
        // Single file selection
        AddFileFromWidePath(current);
    } else {
        // Multiple selection: the first entry is the directory
        wcsncpy(directory, current, MAX_PATH - 1);
        directory[MAX_PATH - 1] = L'\0';
        current += first_len + 1;

        while (*current && g_fileCount < 10) {
            wchar_t full_path[512];
            _snwprintf_s(full_path, _countof(full_path), _TRUNCATE, L"%s\\%s", directory, current);
            AddFileFromWidePath(full_path);
            current += wcslen(current) + 1;
        }
        
        if (*current && g_fileCount >= 10) {
            MessageBox(g_hMainWnd, L"\uD30C\uC77C\uC740 \uCD5C\uB300 10\uAC1C\uB9CC \uC120\uD0DD\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4. \uCD5C\uB300 10\uAC1C\uB9CC \uC120\uD0DD\uB418\uC5C8\uC2B5\uB2C8\uB2E4.", L"\uC624\uB958", MB_OK | MB_ICONWARNING);
            UpdateStatus(L"\uC624\uB958: \uD30C\uC77C\uC740 \uCD5C\uB300 10\uAC1C\uB9CC \uC120\uD0DD\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.");
        }
    }

    wchar_t status[256];
    swprintf(status, 256, L"%d\uAC1C\uC758 \uD30C\uC77C\uC774 \uC120\uD0DD\uB418\uC5C8\uC2B5\uB2C8\uB2E4.", g_fileCount);
    UpdateStatus(status);
}

// Delete selected file from list
void DeleteSelectedFile(void) {
    if (!g_hFileList || g_fileCount == 0) {
        return;
    }
    
    int sel = (int)SendMessage(g_hFileList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR || sel < 0 || sel >= g_fileCount) {
        MessageBox(g_hMainWnd, L"\uC120\uD0DD\uD55C \uD30C\uC77C\uC774 \uC5C6\uC2B5\uB2C8\uB2E4.", L"\uC624\uB958", MB_OK | MB_ICONWARNING);
        return;
    }
    
    // Remove from listbox
    SendMessage(g_hFileList, LB_DELETESTRING, sel, 0);
    
    // Shift array elements
    for (int i = sel; i < g_fileCount - 1; i++) {
        strncpy(g_droppedFiles[i], g_droppedFiles[i + 1], sizeof(g_droppedFiles[i]) - 1);
        g_droppedFiles[i][sizeof(g_droppedFiles[i]) - 1] = '\0';
    }
    
    g_fileCount--;
    
    // Update selection
    if (sel < g_fileCount) {
        SendMessage(g_hFileList, LB_SETCURSEL, sel, 0);
    } else if (g_fileCount > 0) {
        SendMessage(g_hFileList, LB_SETCURSEL, g_fileCount - 1, 0);
    }
    
    wchar_t status[256];
    swprintf(status, 256, L"%d\uAC1C\uC758 \uD30C\uC77C\uC774 \uC120\uD0DD\uB418\uC5C8\uC2B5\uB2C8\uB2E4.", g_fileCount);
    UpdateStatus(status);
}

// Encrypt selected files
void EncryptFiles(void) {
    if (g_fileCount == 0) {
        UpdateStatus(L"\uC624\uB958: \uD30C\uC77C\uC744 \uBA3C\uC800 \uB4DC\uB798\uADF8 \uC564 \uB4DC\uB86D\uD558\uC138\uC694.");
        return;
    }
    
    // Retrieve password from UI
    wchar_t wpassword[32];
    GetWindowText(g_hPasswordEdit, wpassword, 32);
    
    if (wcslen(wpassword) == 0) {
        UpdateStatus(L"\uC624\uB958: \uD328\uC2A4\uC6CC\uB4DC\uB97C \uC785\uB825\uD558\uC138\uC694.");
        return;
    }
    
    // Convert UTF-16 password to ANSI
    char password[32];
    WideCharToMultiByte(CP_ACP, 0, wpassword, -1, password, sizeof(password), NULL, NULL);
    
    if (!validate_password(password)) {
        UpdateStatus(L"\uC624\uB958: \uD328\uC2A4\uC6CC\uB4DC\uB294 \uC601\uBB38+\uC22B\uC790 (\uB300\uC18C\uBB38\uC790) \uCD5C\uB300 10\uC790\uC5EC\uC57C \uD569\uB2C8\uB2E4.");
        return;
    }
    
    int aes_key_bits = GetSelectedAESBits();
    int success_count = 0;
    int fail_count = 0;
    
    for (int i = 0; i < g_fileCount; i++) {
        // Get output filename from user
        wchar_t woutput_path[MAX_PATH] = {0};
        OPENFILENAME ofn;
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hMainWnd;
        ofn.lpstrFilter = L"\uC554\uD638\uD654 \uD30C\uC77C (*.enc)\0*.enc\0\uBAA8\uB4E0 \uD30C\uC77C (*.*)\0*.*\0";
        ofn.lpstrFile = woutput_path;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
        ofn.lpstrDefExt = L"enc";
        
        // Set default filename
        wchar_t winput_path[512];
        MultiByteToWideChar(CP_UTF8, 0, g_droppedFiles[i], -1, winput_path, 512);
        wchar_t* last_slash = wcsrchr(winput_path, L'\\');
        if (!last_slash) last_slash = wcsrchr(winput_path, L'/');
        if (last_slash) {
            wcscpy_s(woutput_path, MAX_PATH, last_slash + 1);
            wchar_t* last_dot = wcsrchr(woutput_path, L'.');
            if (last_dot) {
                *last_dot = L'\0';
            }
            wcscat_s(woutput_path, MAX_PATH, L".enc");
        }
        
        if (!GetSaveFileName(&ofn)) {
            fail_count++;
            continue;
        }
        
        // Convert wide char path to UTF-8
        char output_path[512];
        WideCharToMultiByte(CP_UTF8, 0, woutput_path, -1, output_path, sizeof(output_path), NULL, NULL);
        
        if (encrypt_file(g_droppedFiles[i], output_path, aes_key_bits, password)) {
            success_count++;
        } else {
            fail_count++;
        }
    }
    
    wchar_t status[256];
    swprintf(status, 256, L"\uC554\uD638\uD654 \uC644\uB8CC: \uC131\uACF5 %d\uAC1C, \uC2E4\uD328 %d\uAC1C", success_count, fail_count);
    UpdateStatus(status);
    
    // Clear password field after encryption
    SetWindowText(g_hPasswordEdit, L"");
    
    // Clear the list if every file succeeded
    if (fail_count == 0) {
        ClearFileList();
    }
}

// Decrypt selected files
void DecryptFiles(void) {
    if (g_fileCount == 0) {
        UpdateStatus(L"\uC624\uB958: \uD30C\uC77C\uC744 \uBA3C\uC800 \uB4DC\uB798\uADF8 \uC564 \uB4DC\uB86D\uD558\uC138\uC694.");
        return;
    }
    
    // Retrieve password from UI
    wchar_t wpassword[32];
    GetWindowText(g_hPasswordEdit, wpassword, 32);
    
    if (wcslen(wpassword) == 0) {
        UpdateStatus(L"\uC624\uB958: \uD328\uC2A4\uC6CC\uB4DC\uB97C \uC785\uB825\uD558\uC138\uC694.");
        return;
    }
    
    // Convert UTF-16 password to ANSI
    char password[32];
    WideCharToMultiByte(CP_ACP, 0, wpassword, -1, password, sizeof(password), NULL, NULL);
    
    int success_count = 0;
    int fail_count = 0;
    int password_fail_count = 0;
    int invalid_file_count = 0;
    
    for (int i = 0; i < g_fileCount; i++) {
        // Ensure the file has the .enc extension
        if (strlen(g_droppedFiles[i]) < 4 || 
            strcmp(g_droppedFiles[i] + strlen(g_droppedFiles[i]) - 4, ".enc") != 0) {
            MessageBox(g_hMainWnd, L"\uBCF5\uD638\uD654 \uC2DC \uD544\uC694\uD55C \uD30C\uC77C\uC740 .enc\uC785\uB2C8\uB2E4.", L"\uC624\uB958", MB_OK | MB_ICONERROR);
            fail_count++;
            invalid_file_count++;
            continue;
        }
        
        // Read AES key length from file header and inform user
        int aes_key_bits = read_aes_key_length(g_droppedFiles[i]);
        if (aes_key_bits > 0) {
            wchar_t info_msg[256];
            swprintf(info_msg, 256, L"\uD30C\uC77C header\uC5D0\uC11C AES-%d\uB85C \uC554\uD638\uD654\uB418\uC5B4 \uC788\uC2B5\uB2C8\uB2E4. \uC790\uB3D9\uC73C\uB85C \uC120\uD0DD\uB429\uB2C8\uB2E4.", aes_key_bits);
            UpdateStatus(info_msg);
        }
        
        // Get output filename from user (without extension, will be added by decrypt_file)
        wchar_t woutput_path[MAX_PATH] = {0};
        OPENFILENAME ofn;
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hMainWnd;
        ofn.lpstrFilter = L"\uBAA8\uB4E0 \uD30C\uC77C (*.*)\0*.*\0";
        ofn.lpstrFile = woutput_path;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
        
        // Set default filename (remove .enc extension)
        wchar_t winput_path[512];
        MultiByteToWideChar(CP_UTF8, 0, g_droppedFiles[i], -1, winput_path, 512);
        wchar_t* last_slash = wcsrchr(winput_path, L'\\');
        if (!last_slash) last_slash = wcsrchr(winput_path, L'/');
        if (last_slash) {
            wcscpy_s(woutput_path, MAX_PATH, last_slash + 1);
            // Remove .enc extension
            wchar_t* last_dot = wcsrchr(woutput_path, L'.');
            if (last_dot && wcscmp(last_dot, L".enc") == 0) {
                *last_dot = L'\0';
            }
        }
        
        if (!GetSaveFileName(&ofn)) {
            fail_count++;
            continue;
        }
        
        // Convert wide char path to UTF-8
        char output_path[512];
        WideCharToMultiByte(CP_UTF8, 0, woutput_path, -1, output_path, sizeof(output_path), NULL, NULL);
        
        char final_output_path[512];
        if (decrypt_file(g_droppedFiles[i], output_path, password, final_output_path, sizeof(final_output_path))) {
            success_count++;
        } else {
            fail_count++;
            password_fail_count++;
            // Show error message for password failure
            MessageBox(g_hMainWnd, L"\uD328\uC2A4\uC6CC\uB4DC\uAC00 \uD2C0\uB838\uC2B5\uB2C8\uB2E4.", L"\uBCF5\uD638\uD654 \uC2E4\uD328", MB_OK | MB_ICONERROR);
        }
    }
    
    wchar_t status[256];
    if (fail_count > 0) {
        // Only show password check message if password failures occurred (not invalid file extensions)
        if (password_fail_count > 0) {
            swprintf(status, 256, L"\uBCF5\uD638\uD654 \uC644\uB8CC: \uC131\uACF5 %d\uAC1C, \uC2E4\uD328 %d\uAC1C (\uD328\uC2A4\uC6CC\uB4DC \uD655\uC778 \uD544\uC694)", success_count, fail_count);
        } else {
            swprintf(status, 256, L"\uBCF5\uD638\uD654 \uC644\uB8CC: \uC131\uACF5 %d\uAC1C, \uC2E4\uD328 %d\uAC1C", success_count, fail_count);
        }
    } else {
        swprintf(status, 256, L"\uBB34\uACB0\uC131\uC774 \uAC80\uC99D\uB418\uC5C8\uC2B5\uB2C8\uB2E4. \uBCF5\uD638\uD654 \uC644\uB8CC: %d\uAC1C", success_count);
    }
    UpdateStatus(status);
    
    // Clear the list if every file succeeded
    if (fail_count == 0) {
        ClearFileList();
    }
}
#endif // PLATFORM_WINDOWS

