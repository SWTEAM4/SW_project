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
};

#endif // MAINWINDOW_H

