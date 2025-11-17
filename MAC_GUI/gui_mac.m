//
//  gui_mac.m
//  File Encryption/Decryption GUI for macOS
//
//  macOS GUI implementation using Cocoa
//

#import <Cocoa/Cocoa.h>
#import <Foundation/Foundation.h>
#include "file_crypto.h"
#include "platform_utils.h"

// Global variables
static NSWindow* g_mainWindow = nil;
static NSTextField* g_passwordField = nil;
static NSPopUpButton* g_aesCombo = nil;
static NSTextView* g_statusText = nil;
static NSTableView* g_fileList = nil;
static NSMutableArray* g_droppedFiles = nil;

// Function declarations
void UpdateStatus(NSString* message);
void EncryptFiles(void);
void DecryptFiles(void);
int GetSelectedAESBits(void);

@interface AppDelegate : NSObject <NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate, NSWindowDelegate>
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    // Create main window
    NSRect frame = NSMakeRect(100, 100, 600, 500);
    g_mainWindow = [[NSWindow alloc] initWithContentRect:frame
                                               styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable
                                                 backing:NSBackingStoreBuffered
                                                   defer:NO];
    [g_mainWindow setTitle:@"파일 암호화/복호화 프로그램"];
    [g_mainWindow center];
    [g_mainWindow setAcceptsMouseMovedEvents:YES];
    [g_mainWindow setDelegate:self];
    
    NSView* contentView = [g_mainWindow contentView];
    
    // File list
    NSScrollView* scrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(10, 300, 560, 100)];
    g_fileList = [[NSTableView alloc] init];
    NSTableColumn* column = [[NSTableColumn alloc] initWithIdentifier:@"File"];
    [column setWidth:550];
    [g_fileList addTableColumn:column];
    [g_fileList setDataSource:self];
    [g_fileList setDelegate:self];
    [scrollView setDocumentView:g_fileList];
    [scrollView setHasVerticalScroller:YES];
    [contentView addSubview:scrollView];
    
    // Password field
    NSTextField* passwordLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(10, 270, 250, 20)];
    [passwordLabel setStringValue:@"패스워드 (영문+숫자, 최대 10자):"];
    [passwordLabel setBezeled:NO];
    [passwordLabel setDrawsBackground:NO];
    [passwordLabel setEditable:NO];
    [contentView addSubview:passwordLabel];
    
    g_passwordField = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(10, 245, 250, 25)];
    [g_passwordField setEditable:YES];
    [g_passwordField setEnabled:YES];
    [g_passwordField setSelectable:YES];
    [g_passwordField setBordered:YES];
    [g_passwordField setBezeled:YES];
    [g_passwordField setPlaceholderString:@"패스워드를 입력하세요"];
    [g_passwordField setStringValue:@""];
    [contentView addSubview:g_passwordField];
    
    // AES selection
    NSTextField* aesLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(280, 270, 200, 20)];
    [aesLabel setStringValue:@"AES 키 길이 (암호화용):"];
    [aesLabel setBezeled:NO];
    [aesLabel setDrawsBackground:NO];
    [aesLabel setEditable:NO];
    [contentView addSubview:aesLabel];
    
    g_aesCombo = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(280, 245, 150, 25)];
    [g_aesCombo addItemWithTitle:@"AES-128"];
    [g_aesCombo addItemWithTitle:@"AES-192"];
    [g_aesCombo addItemWithTitle:@"AES-256"];
    [g_aesCombo selectItemAtIndex:0];
    [contentView addSubview:g_aesCombo];
    
    // Buttons
    NSButton* encryptButton = [[NSButton alloc] initWithFrame:NSMakeRect(450, 245, 120, 30)];
    [encryptButton setTitle:@"암호화"];
    [encryptButton setButtonType:NSButtonTypeMomentaryPushIn];
    [encryptButton setBezelStyle:NSBezelStyleRounded];
    [encryptButton setTarget:self];
    [encryptButton setAction:@selector(encryptClicked:)];
    [contentView addSubview:encryptButton];
    
    NSButton* decryptButton = [[NSButton alloc] initWithFrame:NSMakeRect(450, 210, 120, 30)];
    [decryptButton setTitle:@"복호화"];
    [decryptButton setButtonType:NSButtonTypeMomentaryPushIn];
    [decryptButton setBezelStyle:NSBezelStyleRounded];
    [decryptButton setTarget:self];
    [decryptButton setAction:@selector(decryptClicked:)];
    [contentView addSubview:decryptButton];
    
    NSButton* fileSelectButton = [[NSButton alloc] initWithFrame:NSMakeRect(450, 175, 120, 25)];
    [fileSelectButton setTitle:@"파일 선택"];
    [fileSelectButton setButtonType:NSButtonTypeMomentaryPushIn];
    [fileSelectButton setBezelStyle:NSBezelStyleRounded];
    [fileSelectButton setTarget:self];
    [fileSelectButton setAction:@selector(fileSelectClicked:)];
    [contentView addSubview:fileSelectButton];
    
    // Status text
    NSScrollView* statusScrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(10, 10, 560, 150)];
    g_statusText = [[NSTextView alloc] init];
    [g_statusText setEditable:NO];
    [statusScrollView setDocumentView:g_statusText];
    [statusScrollView setHasVerticalScroller:YES];
    [contentView addSubview:statusScrollView];
    
    // Initialize file list
    g_droppedFiles = [[NSMutableArray alloc] init];
    
    // Get executable path
    NSString* exePath = [[NSBundle mainBundle] executablePath];
    UpdateStatus([NSString stringWithFormat:@"파일을 드래그 앤 드롭하여 시작하세요.\n\n실행 경로: %@", exePath]);
    
    // Activate the application and show window
    [NSApp activateIgnoringOtherApps:YES];
    [g_mainWindow makeKeyAndOrderFront:nil];
    
    // Set focus to password field after a short delay to ensure window is fully ready
    [self performSelector:@selector(setPasswordFieldFocus) withObject:nil afterDelay:0.1];
}

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    return [g_droppedFiles count];
}

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
    if (row < [g_droppedFiles count]) {
        NSString* path = [g_droppedFiles objectAtIndex:row];
        return [path lastPathComponent];
    }
    return nil;
}

- (void)encryptClicked:(id)sender {
    EncryptFiles();
}

- (void)decryptClicked:(id)sender {
    DecryptFiles();
}

- (void)fileSelectClicked:(id)sender {
    NSOpenPanel* panel = [NSOpenPanel openPanel];
    [panel setAllowsMultipleSelection:YES];
    [panel setCanChooseFiles:YES];
    [panel setCanChooseDirectories:NO];
    
    if ([panel runModal] == NSModalResponseOK) {
        NSArray* urls = [panel URLs];
        for (NSURL* url in urls) {
            NSString* path = [url path];
            if (![g_droppedFiles containsObject:path] && [g_droppedFiles count] < 10) {
                [g_droppedFiles addObject:path];
            }
        }
        [g_fileList reloadData];
        UpdateStatus([NSString stringWithFormat:@"%lu개의 파일이 선택되었습니다.", (unsigned long)[g_droppedFiles count]]);
    }
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}

- (void)setPasswordFieldFocus {
    if (g_passwordField && g_mainWindow) {
        [g_mainWindow makeKeyWindow];
        [g_mainWindow makeFirstResponder:g_passwordField];
        [g_passwordField becomeFirstResponder];
    }
}

- (void)windowDidBecomeKey:(NSNotification *)notification {
    // When window becomes key, set focus to password field
    if (g_passwordField) {
        [self performSelector:@selector(setPasswordFieldFocus) withObject:nil afterDelay:0.05];
    }
}

@end

void UpdateStatus(NSString* message) {
    if (g_statusText) {
        NSString* exePath = [[NSBundle mainBundle] executablePath];
        NSString* fullMessage = [NSString stringWithFormat:@"%@\n\n실행 경로: %@", message, exePath];
        [g_statusText setString:fullMessage];
    }
}

int GetSelectedAESBits(void) {
    if (g_aesCombo) {
        NSInteger sel = [g_aesCombo indexOfSelectedItem];
        if (sel == 0) return 128;
        else if (sel == 1) return 192;
        else if (sel == 2) return 256;
    }
    return 128;
}

void EncryptFiles(void) {
    if ([g_droppedFiles count] == 0) {
        UpdateStatus(@"오류: 파일을 먼저 선택하세요.");
        return;
    }
    
    NSString* password = [g_passwordField stringValue];
    if ([password length] == 0) {
        UpdateStatus(@"오류: 패스워드를 입력하세요.");
        return;
    }
    
    const char* passwordCStr = [password UTF8String];
    char passwordAnsi[32];
    strncpy(passwordAnsi, passwordCStr, sizeof(passwordAnsi) - 1);
    passwordAnsi[sizeof(passwordAnsi) - 1] = '\0';
    
    if (!validate_password(passwordAnsi)) {
        UpdateStatus(@"오류: 패스워드는 영문+숫자 (대소문자) 최대 10자여야 합니다.");
        return;
    }
    
    int aes_key_bits = GetSelectedAESBits();
    int success_count = 0;
    int fail_count = 0;
    
    for (NSString* filePath in g_droppedFiles) {
        const char* inputPath = [filePath UTF8String];
        
        // Show save dialog
        NSSavePanel* savePanel = [NSSavePanel savePanel];
        [savePanel setAllowedFileTypes:@[@"enc"]];
        [savePanel setCanCreateDirectories:YES];
        [savePanel setNameFieldStringValue:[[filePath lastPathComponent] stringByDeletingPathExtension]];
        
        if ([savePanel runModal] == NSModalResponseOK) {
            NSURL* url = [savePanel URL];
            const char* outputPath = [[url path] UTF8String];
            
            if (encrypt_file(inputPath, outputPath, aes_key_bits, passwordAnsi)) {
                success_count++;
            } else {
                fail_count++;
            }
        } else {
            fail_count++;
        }
    }
    
    NSString* status = [NSString stringWithFormat:@"암호화 완료: 성공 %d개, 실패 %d개", success_count, fail_count];
    UpdateStatus(status);
    
    [g_passwordField setStringValue:@""];
    
    if (fail_count == 0) {
        [g_droppedFiles removeAllObjects];
        [g_fileList reloadData];
    }
}

void DecryptFiles(void) {
    if ([g_droppedFiles count] == 0) {
        UpdateStatus(@"오류: 파일을 먼저 선택하세요.");
        return;
    }
    
    NSString* password = [g_passwordField stringValue];
    if ([password length] == 0) {
        UpdateStatus(@"오류: 패스워드를 입력하세요.");
        return;
    }
    
    const char* passwordCStr = [password UTF8String];
    char passwordAnsi[32];
    strncpy(passwordAnsi, passwordCStr, sizeof(passwordAnsi) - 1);
    passwordAnsi[sizeof(passwordAnsi) - 1] = '\0';
    
    int success_count = 0;
    int fail_count = 0;
    int password_fail_count = 0;
    
    for (NSString* filePath in g_droppedFiles) {
        const char* inputPath = [filePath UTF8String];
        
        // Check .enc extension
        if (![[filePath pathExtension] isEqualToString:@"enc"]) {
            NSAlert* alert = [[NSAlert alloc] init];
            [alert setMessageText:@"오류"];
            [alert setInformativeText:@"복호화 시 필요한 파일은 .enc입니다."];
            [alert setAlertStyle:NSAlertStyleWarning];
            [alert runModal];
            fail_count++;
            continue;
        }
        
        // Read AES key length
        int aes_key_bits = read_aes_key_length(inputPath);
        if (aes_key_bits > 0) {
            NSString* infoMsg = [NSString stringWithFormat:@"파일 header에서 AES-%d로 암호화되어 있습니다. 자동으로 선택됩니다.", aes_key_bits];
            UpdateStatus(infoMsg);
        }
        
        // Show save dialog
        NSSavePanel* savePanel = [NSSavePanel savePanel];
        [savePanel setCanCreateDirectories:YES];
        NSString* defaultName = [[filePath lastPathComponent] stringByDeletingPathExtension];
        [savePanel setNameFieldStringValue:defaultName];
        
        if ([savePanel runModal] == NSModalResponseOK) {
            NSURL* url = [savePanel URL];
            const char* outputPath = [[url path] UTF8String];
            char final_output_path[512];
            
            if (decrypt_file(inputPath, outputPath, passwordAnsi, final_output_path, sizeof(final_output_path))) {
                success_count++;
            } else {
                fail_count++;
                password_fail_count++;
                NSAlert* alert = [[NSAlert alloc] init];
                [alert setMessageText:@"복호화 실패"];
                [alert setInformativeText:@"패스워드가 틀렸습니다."];
                [alert setAlertStyle:NSAlertStyleCritical];
                [alert runModal];
            }
        } else {
            fail_count++;
        }
    }
    
    NSString* status;
    if (fail_count > 0) {
        if (password_fail_count > 0) {
            status = [NSString stringWithFormat:@"복호화 완료: 성공 %d개, 실패 %d개 (패스워드 확인 필요)", success_count, fail_count];
        } else {
            status = [NSString stringWithFormat:@"복호화 완료: 성공 %d개, 실패 %d개", success_count, fail_count];
        }
    } else {
        status = [NSString stringWithFormat:@"무결성이 검증되었습니다. 복호화 완료: %d개", success_count];
    }
    UpdateStatus(status);
    
    if (fail_count == 0) {
        [g_droppedFiles removeAllObjects];
        [g_fileList reloadData];
    }
}

int main(int argc, char* argv[]) {
    @autoreleasepool {
        NSApplication* app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        AppDelegate* delegate = [[AppDelegate alloc] init];
        [app setDelegate:delegate];
        [app activateIgnoringOtherApps:YES];
        [app run];
    }
    return 0;
}

