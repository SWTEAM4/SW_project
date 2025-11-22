#define _CRT_SECURE_NO_WARNINGS

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <io.h>
#pragma comment(lib, "comctl32.lib")  // 이 줄을 추가하세요
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
#define IDC_PROGRESS_WINDOW       1010
#define IDC_PROGRESS_BAR          1011
#define IDC_PROGRESS_TEXT         1012
#define IDC_PROGRESS_FILE_TEXT    1013

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
static HWND g_hProgressWnd = NULL;
static HWND g_hProgressBar = NULL;
static HWND g_hProgressText = NULL;
static HWND g_hProgressFileText = NULL;
static char g_droppedFiles[10][512];  // Stores up to 10 file paths
static int g_fileCount = 0;

// 진행률 추적을 위한 전역 변수 추가
static long g_currentFileSize = 0;
static int g_currentFileIndex = 0;
static int g_totalFiles = 0;

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
void CreateProgressWindow(void);
void DestroyProgressWindow(void);
void UpdateProgressWindow(int current_file, int total_files, const char* filename);
LRESULT CALLBACK ProgressWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

// 진행률 콜백 함수
void EncryptionProgressCallback(long processed, long total, void* user_data) {
    if (g_currentFileSize > 0 && g_hProgressBar) {
        // 현재 파일 내부 진행률
        int file_percent = (int)((double)processed / g_currentFileSize * 100.0);
        if (file_percent > 100) file_percent = 100;
        
        // 전체 진행률 계산: (이전 파일들) + (현재 파일 진행률)
        int prev_files_contribution = g_currentFileIndex * 100 / g_totalFiles;
        int current_file_contribution = file_percent / g_totalFiles;
        int total_percent = prev_files_contribution + current_file_contribution;
        if (total_percent > 100) total_percent = 100;
        
        SendMessage(g_hProgressBar, PBM_SETPOS, total_percent, 0);
        
        // 텍스트 업데이트
        wchar_t progress_text[256];
        swprintf(progress_text, 256, L"Progress: %d / %d files (%d%%)", 
                 g_currentFileIndex + 1, g_totalFiles, file_percent);
        if (g_hProgressText) {
            SetWindowText(g_hProgressText, progress_text);
        }
        
        // 메시지 처리
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
}

// Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize common controls for progress bar
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);
    
    const wchar_t CLASS_NAME[] = L"FileCryptoWindowClass";
    
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    if (!RegisterClass(&wc)) {
        MessageBox(NULL, L"Window class registration failed", L"Error", MB_OK | MB_ICONERROR);
        return 0;
    }
    
    g_hMainWnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"File Encryption/Decryption Program",
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
            DrawText(hdc, L"Drag and drop files here", -1, &rect, 
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
    CreateWindow(L"STATIC", L"Selected Files (requires .enc format for decryption):", WS_CHILD | WS_VISIBLE,
                 10, 140, 300, 20, hwnd, NULL, NULL, NULL);
    
    g_hFileList = CreateWindow(
        L"LISTBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER,
        10, 165, 560, 100,
        hwnd, (HMENU)IDC_FILE_LIST, NULL, NULL
    );
    
    // Password input
    CreateWindow(L"STATIC", L"Password (alphanumeric, max 10 characters):", WS_CHILD | WS_VISIBLE,
                 10, 275, 250, 20, hwnd, NULL, NULL, NULL);
    
    g_hPasswordEdit = CreateWindow(
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
        10, 300, 250, 25,
        hwnd, (HMENU)IDC_PASSWORD_EDIT, NULL, NULL
    );
    
    // AES selection
    CreateWindow(L"STATIC", L"AES Key Length (for encryption):", WS_CHILD | WS_VISIBLE,
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
        L"BUTTON", L"Encrypt",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        450, 300, 120, 30,
        hwnd, (HMENU)IDC_ENCRYPT_BUTTON, NULL, NULL
    );
    
    // Decrypt button
    CreateWindow(
        L"BUTTON", L"Decrypt",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        450, 335, 120, 30,
        hwnd, (HMENU)IDC_DECRYPT_BUTTON, NULL, NULL
    );

    // File selection button
    g_hFileSelectButton = CreateWindow(
        L"BUTTON", L"Select Files",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        450, 270, 120, 25,
        hwnd, (HMENU)IDC_FILE_SELECT_BUTTON, NULL, NULL
    );
    
    // File delete button (top right of file list)
    g_hFileDeleteButton = CreateWindow(
        L"BUTTON", L"Delete File",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        450, 140, 120, 25,
        hwnd, (HMENU)IDC_FILE_DELETE_BUTTON, NULL, NULL
    );
    
    // Status text
    wchar_t exe_path[MAX_PATH];
    GetModuleFileNameW(NULL, exe_path, MAX_PATH);
    wchar_t initial_status[512];
    swprintf(initial_status, 512, L"Drag and drop files here to start.\n\nExecutable path: %s", exe_path);
    
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
        swprintf(full_message, 512, L"%s\n\nExecutable path: %s", message, exe_path);
        SetWindowText(g_hStatusText, full_message);
    }
}

// Handle dropped files
void ProcessDroppedFiles(HDROP hDrop) {
    ClearFileList();
    
    UINT fileCount = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, 0);
    
    if (fileCount > 10) {
        MessageBox(g_hMainWnd, L"Maximum 10 files can be selected.", L"Error", MB_OK | MB_ICONWARNING);
        UpdateStatus(L"Error: Maximum 10 files can be selected.");
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
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
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
            MessageBox(g_hMainWnd, L"Maximum 10 files can be selected. Only 10 files were selected.", L"Error", MB_OK | MB_ICONWARNING);
            UpdateStatus(L"Error: Maximum 10 files can be selected.");
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
        MessageBox(g_hMainWnd, L"No file selected.", L"Error", MB_OK | MB_ICONWARNING);
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

// Progress window procedure
LRESULT CALLBACK ProgressWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            return 0;
            
        case WM_CLOSE:
            // Prevent closing during encryption
            return 0;
            
        case WM_DESTROY:
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Create progress window
void CreateProgressWindow(void) {
    if (g_hProgressWnd) {
        DestroyWindow(g_hProgressWnd);
        g_hProgressWnd = NULL;
    }
    
    const wchar_t PROGRESS_CLASS_NAME[] = L"ProgressWindowClass";
    
    WNDCLASS wc = {0};
    wc.lpfnWndProc = ProgressWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = PROGRESS_CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    RegisterClass(&wc);
    
    // Center the window on screen
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int windowWidth = 500;
    int windowHeight = 200;
    int x = (screenWidth - windowWidth) / 2;
    int y = (screenHeight - windowHeight) / 2;
    
    g_hProgressWnd = CreateWindowEx(
        WS_EX_DLGMODALFRAME,
        PROGRESS_CLASS_NAME,
        L"Encryption in progress...",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        x, y,
        windowWidth, windowHeight,
        g_hMainWnd, NULL, GetModuleHandle(NULL), NULL
    );
    
    if (g_hProgressWnd == NULL) {
        return;
    }
    
    // Progress text label
    CreateWindow(L"STATIC", L"Encryption in progress...",
                 WS_CHILD | WS_VISIBLE,
                 20, 20, 460, 25,
                 g_hProgressWnd, (HMENU)IDC_PROGRESS_TEXT, NULL, NULL);
    
    // Current file name label
    g_hProgressFileText = CreateWindow(L"STATIC", L"",
                                       WS_CHILD | WS_VISIBLE | SS_LEFT,
                                       20, 50, 460, 25,
                                       g_hProgressWnd, (HMENU)IDC_PROGRESS_FILE_TEXT, NULL, NULL);
    
    // Progress bar
    g_hProgressBar = CreateWindow(
        PROGRESS_CLASS, NULL,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        20, 90, 460, 25,
        g_hProgressWnd, (HMENU)IDC_PROGRESS_BAR, NULL, NULL
    );
    
    if (g_hProgressBar) {
        SendMessage(g_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
    }
    
    ShowWindow(g_hProgressWnd, SW_SHOW);
    UpdateWindow(g_hProgressWnd);
    
    // Process messages to ensure window is displayed
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

// Destroy progress window
void DestroyProgressWindow(void) {
    if (g_hProgressWnd) {
        DestroyWindow(g_hProgressWnd);
        g_hProgressWnd = NULL;
        g_hProgressBar = NULL;
        g_hProgressText = NULL;
        g_hProgressFileText = NULL;
    }
}

// Update progress window
void UpdateProgressWindow(int current_file, int total_files, const char* filename) {
    if (!g_hProgressWnd || !g_hProgressBar) {
        return;
    }
    
    // Update progress bar
    int percent = (int)((double)current_file / total_files * 100.0);
    if (percent > 100) percent = 100;
    SendMessage(g_hProgressBar, PBM_SETPOS, percent, 0);
    
    // Update progress text
    wchar_t progress_text[256];
    swprintf(progress_text, 256, L"Progress: %d / %d files", current_file, total_files);
    if (g_hProgressText) {
        SetWindowText(g_hProgressText, progress_text);
    }
    
    // Update file name
    if (g_hProgressFileText && filename) {
        wchar_t wfilename[512];
        MultiByteToWideChar(CP_UTF8, 0, filename, -1, wfilename, 512);
        
        // Extract just the filename
        wchar_t* last_slash = wcsrchr(wfilename, L'\\');
        if (!last_slash) last_slash = wcsrchr(wfilename, L'/');
        if (last_slash) {
            SetWindowText(g_hProgressFileText, last_slash + 1);
        } else {
            SetWindowText(g_hProgressFileText, wfilename);
        }
    }
    
    // Process messages to update UI
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

// Encrypt selected files
void EncryptFiles(void) {
    if (g_fileCount == 0) {
        UpdateStatus(L"Error: Please drag and drop files first.");
        return;
    }
    
    // Retrieve password from UI
    wchar_t wpassword[32];
    GetWindowText(g_hPasswordEdit, wpassword, 32);
    
    if (wcslen(wpassword) == 0) {
        UpdateStatus(L"Error: Please enter password.");
        return;
    }
    
    // Convert UTF-16 password to ANSI
    char password[32];
    WideCharToMultiByte(CP_ACP, 0, wpassword, -1, password, sizeof(password), NULL, NULL);
    
    if (!validate_password(password)) {
        UpdateStatus(L"Error: Password must be alphanumeric (case-sensitive) with maximum 10 characters.");
        return;
    }
    
    int aes_key_bits = GetSelectedAESBits();
    int success_count = 0;
    int fail_count = 0;
    
    g_totalFiles = g_fileCount;
    
    // Create progress window
    CreateProgressWindow();
    
    for (int i = 0; i < g_fileCount; i++) {
        g_currentFileIndex = i;
        
        // 파일 크기 확인
        FILE* f = platform_fopen(g_droppedFiles[i], "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            g_currentFileSize = ftell(f);
            fclose(f);
        } else {
            g_currentFileSize = 0;
        }
        
        // Update progress window
        UpdateProgressWindow(i, g_fileCount, g_droppedFiles[i]);
        
        // Get output filename from user
        wchar_t woutput_path[MAX_PATH] = {0};
        OPENFILENAME ofn;
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hProgressWnd ? g_hProgressWnd : g_hMainWnd;
        ofn.lpstrFilter = L"Encrypted Files (*.enc)\0*.enc\0All Files (*.*)\0*.*\0";
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
        
        // 암호화 - 진행률 콜백 사용
        if (encrypt_file_with_progress(g_droppedFiles[i], output_path, aes_key_bits, password,
                                       EncryptionProgressCallback, NULL)) {
            success_count++;
        } else {
            fail_count++;
        }
    }
    
    // Update progress to 100%
    UpdateProgressWindow(g_fileCount, g_fileCount, NULL);
    
    // Destroy progress window
    DestroyProgressWindow();
    
    wchar_t status[256];
    swprintf(status, 256, L"Encryption completed: %d succeeded, %d failed", success_count, fail_count);
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
        UpdateStatus(L"Error: Please drag and drop files first.");
        return;
    }
    
    // Retrieve password from UI
    wchar_t wpassword[32];
    GetWindowText(g_hPasswordEdit, wpassword, 32);
    
    if (wcslen(wpassword) == 0) {
        UpdateStatus(L"Error: Please enter password.");
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
            MessageBox(g_hMainWnd, L"Files for decryption must be in .enc format.", L"Error", MB_OK | MB_ICONERROR);
            fail_count++;
            invalid_file_count++;
            continue;
        }
        
        // Read AES key length from file header and inform user
        int aes_key_bits = read_aes_key_length(g_droppedFiles[i]);
        if (aes_key_bits > 0) {
            wchar_t info_msg[256];
            swprintf(info_msg, 256, L"File header shows AES-%d encryption. Automatically selected.", aes_key_bits);
            UpdateStatus(info_msg);
        }
        
        // Get output filename from user (without extension, will be added by decrypt_file)
        wchar_t woutput_path[MAX_PATH] = {0};
        OPENFILENAME ofn;
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hMainWnd;
        ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
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
            MessageBox(g_hMainWnd, L"Password is incorrect.", L"Decryption Failed", MB_OK | MB_ICONERROR);
        }
    }
    
    wchar_t status[256];
    if (fail_count > 0) {
        // Only show password check message if password failures occurred (not invalid file extensions)
        if (password_fail_count > 0) {
            swprintf(status, 256, L"Decryption completed: %d succeeded, %d failed (password verification required)", success_count, fail_count);
        } else {
            swprintf(status, 256, L"Decryption completed: %d succeeded, %d failed", success_count, fail_count);
        }
    } else {
        swprintf(status, 256, L"Integrity verified. Decryption completed: %d file(s)", success_count);
    }
    UpdateStatus(status);
    
    // Clear the list if every file succeeded
    if (fail_count == 0) {
        ClearFileList();
    }
}
#endif // PLATFORM_WINDOWS

