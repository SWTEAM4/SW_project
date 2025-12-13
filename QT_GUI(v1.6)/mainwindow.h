#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QStringList>
#include <QListWidgetItem>
#include "cryptoworker.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

// 매직 문자열 상수 정의
namespace MessageBoxTitles {
    constexpr const char* ERROR_TITLE = "Error";
    constexpr const char* INFO = "Info";
    constexpr const char* SUCCESS = "Success";
    constexpr const char* WARNING = "Warning";
}

namespace ErrorMessages {
    constexpr const char* SELECT_FILE_TO_REMOVE = "Please select a file to remove.";
    constexpr const char* SELECT_FILE_FIRST = "Please select a file first.";
    constexpr const char* SELECT_FILE_TO_ENCRYPT = "Please select a file to encrypt.";
    constexpr const char* SELECT_FILE_TO_DECRYPT = "Please select a file to decrypt.";
    constexpr const char* ENTER_PASSWORD = "Please enter a password.";
    constexpr const char* ENTER_PASSWORD_FOR_DECRYPT = "Please enter the password used for encryption.";
    constexpr const char* INVALID_FILE_SELECTION = "Invalid file selection.";
    constexpr const char* PASSWORD_VALIDATION = "Password must be alphanumeric (case-sensitive) with maximum 10 characters.";
}

namespace FileFilters {
    constexpr const char* ENCRYPTED_FILES = "Encrypted Files (*.enc)";
    constexpr const char* RECOVERED_FILES_BIN = "Recovered Files (*.bin);;All Files (*.*)";
    constexpr const char* RECOVERED_FILES_TEMPLATE = "Recovered Files (*.%1);;All Files (*.*)";
}

namespace DialogTitles {
    constexpr const char* SELECT_FILES = "Select Files";
    constexpr const char* SAVE_ENCRYPTED_FILE = "Save Encrypted File";
    constexpr const char* SAVE_DECRYPTED_FILE = "Save Decrypted File";
}

namespace StatusMessages {
    constexpr const char* READY = "Ready";
    constexpr const char* PREPARING_ENCRYPTION = "Preparing encryption...";
    constexpr const char* PREPARING_DECRYPTION = "Preparing decryption...";
    constexpr const char* PROCESSING_TEMPLATE = "Processing %1...";
}

namespace FileExtensions {
    constexpr const char* BIN = ".bin";
}

// 파일 정보를 저장하는 구조체
struct FileInfo {
    QString inputPath;
    QString outputPath;
    bool isEncrypted;  // .enc 파일인지 여부
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    // 드래그앤드롭 이벤트
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private slots:
    void onSelectFiles();
    void onRemoveFile();
    void onFileListSelectionChanged();
    void onBrowseOutputPath();
    void onOutputPathChanged();
    void onEncrypt();
    void onDecrypt();
    void onProgressUpdated(qint64 processed, qint64 total, const QString &fileName);
    void onFinished(bool success, const QString &message);
    void onError(const QString &errorMessage);

private:
    Ui::MainWindow *ui;
    QThread *workerThread;
    CryptoWorker *worker;
    QList<FileInfo> fileList;  // 여러 파일 목록
    bool isEncryptMode;
    int currentFileIndex;  // 현재 처리 중인 파일 인덱스
    int processingFileIndex;  // 현재 암호화/복호화 중인 파일 인덱스
    
    void setupUI();
    void enableButtons(bool enabled);
    void addFilesToList(const QStringList &filePaths);
    void updateFileListDisplay();
    void updateOutputPathForCurrentFile();
    QString generateDefaultOutputPath(const QString &inputPath, bool isEncrypt) const;
    QString resolveSuggestedOutputPath(int index) const;
    QString readExtensionFromHeader(const QString &inputPath) const;
    void resetUI();  // UI 초기화 함수
    void resetUIState();  // 공통 UI 상태 초기화 (진행률 바, 상태 레이블, AES 키 길이)
    int getSelectedAesKeyBits() const;  // 선택된 AES 키 길이 반환 (128/192/256)
    
    // .enc 확장자 처리 유틸리티 함수
    static bool isEncryptedFile(const QString &filePath);
    static QString removeEncExtension(const QString &baseName);
    static QString addEncExtension(const QString &baseName);
    
    // 파일 선택 및 검증
    int getSelectedFileIndex() const;
    
    // 복호화 출력 경로 결정
    void resolveDecryptOutputPath(int index);
    QString resolveAutoDecryptOutputPath(int index) const;
    QString resolveUserDecryptOutputPath(int index, const QString &userPath) const;
    
    // 확장자 정규화
    static QString normalizeExtension(const QString &ext);
    
    // 경로 변환 유틸리티 함수
    static QString toNativePath(const QString &path);
    static QByteArray toNativePathBytes(const QString &path);
    
    // 에러 메시지 표시 헬퍼 함수
    void showError(const QString &message);
    void showCriticalError(const QString &message);
    void showWarning(const QString &message);
    void showSuccess(const QString &message);
    void showInfo(const QString &message);
};

#endif // MAINWINDOW_H

