#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QByteArray>
#include <QMimeData>
#include <QUrl>
#include <QFileInfo>
#include <QListWidgetItem>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QDir>
#include "file_crypto.h"
#include "platform_utils.h"
#include "password_utils.h"
#include <cstdio>
#include <cstring>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , isEncryptMode(true)
    , currentFileIndex(-1)
    , processingFileIndex(-1)
{
    ui->setupUi(this);
    
    // 드래그앤드롭 활성화
    setAcceptDrops(true);
    
    // 워커 스레드 생성
    workerThread = new QThread(this);
    worker = new CryptoWorker();
    worker->moveToThread(workerThread);
    
    // 시그널/슬롯 연결
    connect(worker, &CryptoWorker::progressUpdated,
            this, &MainWindow::onProgressUpdated);
    connect(worker, &CryptoWorker::finished,
            this, &MainWindow::onFinished);
    connect(worker, &CryptoWorker::error,
            this, &MainWindow::onError);
    connect(worker, &CryptoWorker::processFileListRequested,
            worker, &CryptoWorker::processFileList, Qt::QueuedConnection);
    
    workerThread->start();
    
    setupUI();
}

MainWindow::~MainWindow()
{
    workerThread->quit();
    workerThread->wait();
    delete worker;
    delete ui;
}

void MainWindow::setupUI()
{
    // 초기 상태 설정
    ui->progressBar->setMinimum(0);
    ui->progressBar->setMaximum(100);
    ui->progressBar->setValue(0);
    ui->statusLabel->setText("Ready");
    
    // 버튼 연결
    connect(ui->selectFilesButton, &QPushButton::clicked, this, &MainWindow::onSelectFiles);
    connect(ui->removeFileButton, &QPushButton::clicked, this, &MainWindow::onRemoveFile);
    connect(ui->browseOutputButton, &QPushButton::clicked, this, &MainWindow::onBrowseOutputPath);
    connect(ui->outputPathEdit, &QLineEdit::textChanged, this, &MainWindow::onOutputPathChanged);
    connect(ui->fileListWidget, &QListWidget::itemSelectionChanged, 
            this, &MainWindow::onFileListSelectionChanged);
    connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::onEncrypt);
    connect(ui->decryptButton, &QPushButton::clicked, this, &MainWindow::onDecrypt);
    
    // AES 키 길이 기본값
    ui->aes128Radio->setChecked(true);
    
    // 패스워드 입력 필드 설정
    ui->passwordEdit->setEchoMode(QLineEdit::Password);
    
    // 파일 리스트 초기화
    updateFileListDisplay();
}

void MainWindow::enableButtons(bool enabled)
{
    ui->selectFilesButton->setEnabled(enabled);
    ui->removeFileButton->setEnabled(enabled);
    ui->browseOutputButton->setEnabled(enabled);
    ui->encryptButton->setEnabled(enabled);
    ui->decryptButton->setEnabled(enabled);
    ui->aes128Radio->setEnabled(enabled);
    ui->aes192Radio->setEnabled(enabled);
    ui->aes256Radio->setEnabled(enabled);
    ui->fileListWidget->setEnabled(enabled);
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *event)
{
    QStringList filePaths;
    const QMimeData *mimeData = event->mimeData();
    
    if (mimeData->hasUrls()) {
        for (const QUrl &url : mimeData->urls()) {
            QString filePath = url.toLocalFile();
            if (!filePath.isEmpty()) {
                QFileInfo fileInfo(filePath);
                if (fileInfo.isFile()) {
                    filePaths.append(filePath);
                }
            }
        }
    }
    
    if (!filePaths.isEmpty()) {
        addFilesToList(filePaths);
    }
    
    event->acceptProposedAction();
}

void MainWindow::onSelectFiles()
{
    QStringList files = QFileDialog::getOpenFileNames(this, "Select Files");
    if (!files.isEmpty()) {
        addFilesToList(files);
    }
}

void MainWindow::addFilesToList(const QStringList &filePaths)
{
    for (const QString &filePath : filePaths) {
        QFileInfo fileInfo(filePath);
        if (!fileInfo.exists() || !fileInfo.isFile()) {
            continue;
        }
        
        // 중복 체크
        bool alreadyExists = false;
        for (const FileInfo &fi : fileList) {
            if (fi.inputPath == filePath) {
                alreadyExists = true;
                break;
            }
        }
        
        if (!alreadyExists) {
            FileInfo fileInfo;
            fileInfo.inputPath = filePath;
            fileInfo.isEncrypted = filePath.endsWith(".enc", Qt::CaseInsensitive);
            // .enc 파일이면 복호화 모드(false), 아니면 암호화 모드(true)
            bool isEncrypt = !fileInfo.isEncrypted;
            fileInfo.outputPath = generateDefaultOutputPath(filePath, isEncrypt);
            fileList.append(fileInfo);
        }
    }
    
    updateFileListDisplay();
}

void MainWindow::onRemoveFile()
{
    QListWidgetItem *item = ui->fileListWidget->currentItem();
    if (!item) {
        QMessageBox::information(this, "Info", "Please select a file to remove.");
        return;
    }
    
    int index = ui->fileListWidget->row(item);
    if (index >= 0 && index < fileList.size()) {
        fileList.removeAt(index);
        updateFileListDisplay();
    }
}

void MainWindow::onFileListSelectionChanged()
{
    updateOutputPathForCurrentFile();
}

void MainWindow::updateOutputPathForCurrentFile()
{
    QListWidgetItem *item = ui->fileListWidget->currentItem();
    if (!item) {
        ui->outputPathEdit->clear();
        return;
    }
    
    int index = ui->fileListWidget->row(item);
    if (index >= 0 && index < fileList.size()) {
        ui->outputPathEdit->setText(fileList[index].outputPath);
    }
}

QString MainWindow::readExtensionFromHeader(const QString &inputPath) const
{
    QString inputPathNative = QDir::toNativeSeparators(inputPath);
    QByteArray inputBytes = inputPathNative.toUtf8();

    FILE* fin = platform_fopen(inputBytes.constData(), "rb");
    if (!fin) {
        return QString();
    }

    EncFileHeader header;
    QString extension;
    if (fread(&header, 1, sizeof(header), fin) == sizeof(header)) {
        if (memcmp(header.signature, ENC_SIGNATURE, 4) == 0) {
            // format 필드는 null 종료되지 않을 수 있으므로 직접 길이 계산
            size_t ext_len = 0;
            while (ext_len < 8 && header.format[ext_len] != 0) {
                ext_len++;
            }
            if (ext_len > 0) {
                extension = QString::fromUtf8((const char*)header.format, static_cast<int>(ext_len));
            }
        }
    }
    fclose(fin);
    return extension;
}

QString MainWindow::resolveSuggestedOutputPath(int index) const
{
    if (index < 0 || index >= fileList.size()) {
        return QString();
    }

    const FileInfo &fi = fileList[index];
    QFileInfo inputInfo(fi.inputPath);
    QString baseName = inputInfo.completeBaseName();
    if (baseName.endsWith(".enc", Qt::CaseInsensitive)) {
        baseName.chop(4);
    }

    if (isEncryptMode) {
        return generateDefaultOutputPath(fi.inputPath, true);
    }

    QString suggested = inputInfo.path() + QDir::separator() + baseName;
    QString headerExt = readExtensionFromHeader(fi.inputPath);
    if (!headerExt.isEmpty()) {
        if (headerExt.startsWith('.')) {
            suggested += headerExt;
        } else {
            suggested += "." + headerExt;
        }
    } else {
        // 확장자를 모르더라도 .bin 등을 붙여 저장 가능하도록 기본 확장자 제공
        suggested += ".bin";
    }
    return suggested;
}

void MainWindow::onBrowseOutputPath()
{
    QListWidgetItem *item = ui->fileListWidget->currentItem();
    if (!item) {
        QMessageBox::information(this, "Info", "Please select a file first.");
        return;
    }
    
    int index = ui->fileListWidget->row(item);
    if (index < 0 || index >= fileList.size()) {
        return;
    }
    
    QString defaultPath = fileList[index].outputPath;
    if (defaultPath.isEmpty()) {
        defaultPath = resolveSuggestedOutputPath(index);
    }
    
    // .enc 파일인 경우 헤더에서 원본 확장자 읽어서 defaultPath 수정
    if (fileList[index].isEncrypted) {
        QString originalExt = readExtensionFromHeader(fileList[index].inputPath);
        if (!originalExt.isEmpty()) {
            // 입력 파일명에서 직접 baseName 추출
            QFileInfo inputInfo(fileList[index].inputPath);
            QString baseName = inputInfo.completeBaseName();
            // .enc 제거
            if (baseName.endsWith(".enc", Qt::CaseInsensitive)) {
                baseName = baseName.left(baseName.length() - 4);
            }
            // 원본 확장자 추가
            if (!originalExt.startsWith('.')) {
                originalExt = "." + originalExt;
            }
            // 경로는 기존 defaultPath에서 가져오고 파일명만 변경
            QFileInfo pathInfo(defaultPath);
            defaultPath = pathInfo.path() + QDir::separator() + baseName + originalExt;
        }
    }
    
    QString filter;
    if (isEncryptMode) {
        filter = "Encrypted Files (*.enc)";
    } else {
        QString ext = QFileInfo(defaultPath).suffix();
        if (!ext.isEmpty()) {
            filter = QString("Recovered Files (*.%1);;All Files (*.*)").arg(ext);
        } else {
            filter = "Recovered Files (*.bin);;All Files (*.*)";
        }
    }

    QString filePath = QFileDialog::getSaveFileName(this,
        isEncryptMode ? "Save Encrypted File" : "Save Decrypted File",
        defaultPath, filter);
    
    if (!filePath.isEmpty()) {
        ui->outputPathEdit->setText(filePath);
        fileList[index].outputPath = filePath;
    }
}

void MainWindow::onOutputPathChanged()
{
    QListWidgetItem *item = ui->fileListWidget->currentItem();
    if (!item) {
        return;
    }
    
    int index = ui->fileListWidget->row(item);
    if (index >= 0 && index < fileList.size()) {
        QString newPath = ui->outputPathEdit->text().trimmed();
        if (newPath.isEmpty()) {
            // 자동 경로 생성
            fileList[index].outputPath = generateDefaultOutputPath(
                fileList[index].inputPath, isEncryptMode);
        } else {
            fileList[index].outputPath = newPath;
        }
    }
}

QString MainWindow::generateDefaultOutputPath(const QString &inputPath, bool isEncrypt) const
{
    QFileInfo fileInfo(inputPath);
    QString separator = QDir::separator();
    
    if (isEncrypt) {
        return fileInfo.path() + separator + fileInfo.completeBaseName() + ".enc";
    } else {
        // 복호화: 확장자 없이 경로만 반환
        // 복호화 함수가 헤더에서 읽은 원본 확장자를 자동으로 추가함
        QString baseName = fileInfo.completeBaseName();
        if (baseName.endsWith(".enc", Qt::CaseInsensitive)) {
            baseName = baseName.left(baseName.length() - 4);
        }
        // 확장자 없이 경로만 반환 (복호화 함수가 헤더에서 읽은 원본 확장자를 추가)
        return fileInfo.path() + separator + baseName;
    }
}

void MainWindow::updateFileListDisplay()
{
    ui->fileListWidget->clear();
    
    for (int i = 0; i < fileList.size(); ++i) {
        const FileInfo &fi = fileList[i];
        QFileInfo fileInfo(fi.inputPath);
        
        // 입력 파일명: 그대로 표시
        QString inputFileName = fileInfo.fileName();
        
        // 출력 파일명 표시
        QString outputFileName;
        if (fi.isEncrypted) {
            // .enc 파일인 경우: 헤더에서 원본 확장자 읽어서 표시
            QString originalExt = readExtensionFromHeader(fi.inputPath);
            if (!originalExt.isEmpty()) {
                // 입력 파일명에서 .enc 제거하여 baseName 추출
                QString baseName = fileInfo.completeBaseName();
                if (baseName.endsWith(".enc", Qt::CaseInsensitive)) {
                    baseName = baseName.left(baseName.length() - 4);
                }
                // 확장자가 .으로 시작하지 않으면 추가
                if (!originalExt.startsWith('.')) {
                    originalExt = "." + originalExt;
                }
                outputFileName = baseName + originalExt;
            } else {
                // 확장자를 찾을 수 없으면 기본 출력 경로 사용
                outputFileName = QFileInfo(fi.outputPath).fileName();
            }
        } else {
            // 일반 파일인 경우: .enc 확장자로 표시
            QFileInfo outputInfo(fi.outputPath);
            if (outputInfo.suffix().toLower() == "enc") {
                outputFileName = outputInfo.fileName();
            } else {
                // .enc가 없으면 추가
                outputFileName = outputInfo.completeBaseName() + ".enc";
            }
        }
        
        QString displayText = QString("%1 -> %2")
            .arg(inputFileName)
            .arg(outputFileName);
        
        QListWidgetItem *item = new QListWidgetItem(displayText, ui->fileListWidget);
        item->setData(Qt::UserRole, i);  // 인덱스 저장
        ui->fileListWidget->addItem(item);
    }
    
    if (fileList.isEmpty()) {
        ui->outputPathEdit->clear();
    }
}

void MainWindow::onEncrypt()
{
    isEncryptMode = true;
    
    // 현재 선택된 파일 확인
    QListWidgetItem *item = ui->fileListWidget->currentItem();
    if (!item) {
        QMessageBox::warning(this, "Error", "Please select a file to encrypt.");
        return;
    }
    
    int index = ui->fileListWidget->row(item);
    if (index < 0 || index >= fileList.size()) {
        QMessageBox::warning(this, "Error", "Invalid file selection.");
        return;
    }
    
    // 처리 중인 파일 인덱스 저장
    processingFileIndex = index;
    
    QString password = ui->passwordEdit->text();
    if (password.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please enter a password.");
        return;
    }
    
    // 패스워드 검증
    QByteArray passwordBytes = password.toUtf8();
    if (!validate_password(passwordBytes.constData())) {
        QMessageBox::warning(this, "Error", 
            "Password must be alphanumeric (case-sensitive) with maximum 10 characters.");
        return;
    }
    
    // 선택된 파일의 출력 경로 업데이트
    if (fileList[index].outputPath.isEmpty()) {
        fileList[index].outputPath = generateDefaultOutputPath(fileList[index].inputPath, true);
    }
    
    int aesKeyBits = 128;
    if (ui->aes192Radio->isChecked()) {
        aesKeyBits = 192;
    } else if (ui->aes256Radio->isChecked()) {
        aesKeyBits = 256;
    }
    
    ui->progressBar->setValue(0);
    ui->statusLabel->setText("Preparing encryption...");
    enableButtons(false);
    
    // 선택된 파일만 처리
    QList<QPair<QString, QString>> filePairs;
    filePairs.append(qMakePair(fileList[index].inputPath, fileList[index].outputPath));
    
    // 워커 스레드에서 암호화 실행 (시그널 사용)
    emit worker->processFileListRequested(filePairs, true, aesKeyBits, password);
}

void MainWindow::onDecrypt()
{
    isEncryptMode = false;
    
    // 현재 선택된 파일 확인
    QListWidgetItem *item = ui->fileListWidget->currentItem();
    if (!item) {
        QMessageBox::warning(this, "Error", "Please select a file to decrypt.");
        return;
    }
    
    int index = ui->fileListWidget->row(item);
    if (index < 0 || index >= fileList.size()) {
        QMessageBox::warning(this, "Error", "Invalid file selection.");
        return;
    }
    
    // 처리 중인 파일 인덱스 저장
    processingFileIndex = index;
    
    QString password = ui->passwordEdit->text();
    if (password.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please enter the password used for encryption.");
        return;
    }
    
    // 선택된 파일의 출력 경로 업데이트 - 헤더에서 확장자를 읽어서 추가
    QString userPath = fileList[index].outputPath;
    QString autoPath = generateDefaultOutputPath(fileList[index].inputPath, false);
    
    // 경로 정규화하여 비교 (구분자 통일)
    QString normalizedUserPath = QDir::toNativeSeparators(userPath);
    QString normalizedAutoPath = QDir::toNativeSeparators(autoPath);
    
    if (userPath.isEmpty() || normalizedUserPath == normalizedAutoPath) {
        // 자동 경로: 헤더에서 확장자를 읽어서 추가
        QFileInfo fileInfo(fileList[index].inputPath);
        QString baseName = fileInfo.completeBaseName();
        if (baseName.endsWith(".enc", Qt::CaseInsensitive)) {
            baseName = baseName.left(baseName.length() - 4);
        }
        
        // 헤더에서 확장자 읽기
        QString inputPathNative = QDir::toNativeSeparators(fileList[index].inputPath);
        QByteArray inputBytes = inputPathNative.toUtf8();
        
        FILE* fin = platform_fopen(inputBytes.constData(), "rb");
        if (fin) {
            EncFileHeader header;
            if (fread(&header, 1, sizeof(header), fin) == sizeof(header)) {
                // 시그니처 검증
                if (memcmp(header.signature, ENC_SIGNATURE, 4) == 0) {
                    // format 필드는 null 종료되지 않을 수 있으므로 직접 길이 계산
                    size_t ext_len = 0;
                    while (ext_len < 8 && header.format[ext_len] != 0) {
                        ext_len++;
                    }
                    
                    if (ext_len > 0) {
                        QString extension = QString::fromUtf8((const char*)header.format, static_cast<int>(ext_len));
                        fileList[index].outputPath = fileInfo.path() + QDir::separator() + baseName + extension;
                    } else {
                        // 확장자가 없으면 기본 경로 사용
                        fileList[index].outputPath = fileInfo.path() + QDir::separator() + baseName;
                    }
                } else {
                    // 유효하지 않은 파일 형식
                    fileList[index].outputPath = fileInfo.path() + QDir::separator() + baseName;
                }
            } else {
                // 헤더 읽기 실패
                fileList[index].outputPath = fileInfo.path() + QDir::separator() + baseName;
            }
            fclose(fin);
        } else {
            // 파일 열기 실패
            fileList[index].outputPath = fileInfo.path() + QDir::separator() + baseName;
        }
    } else {
        // 사용자가 직접 입력한 경로인 경우: 항상 헤더에서 읽은 원본 확장자로 설정
        QFileInfo pathInfo(userPath);
        QString baseName = pathInfo.completeBaseName();
        
        // 헤더에서 원본 확장자 읽기
        QString originalExt = readExtensionFromHeader(fileList[index].inputPath);
        if (!originalExt.isEmpty()) {
            // 확장자가 .으로 시작하지 않으면 추가
            if (!originalExt.startsWith('.')) {
                originalExt = "." + originalExt;
            }
            // baseName + 원본 확장자로 설정 (사용자가 입력한 확장자는 무시)
            fileList[index].outputPath = pathInfo.path() + QDir::separator() + baseName + originalExt;
        } else {
            // 확장자를 찾을 수 없으면 사용자가 입력한 경로 그대로 사용
            fileList[index].outputPath = userPath;
        }
    }
    
    ui->progressBar->setValue(0);
    ui->statusLabel->setText("Preparing decryption...");
    enableButtons(false);
    
    // 선택된 파일만 처리
    QList<QPair<QString, QString>> filePairs;
    filePairs.append(qMakePair(fileList[index].inputPath, fileList[index].outputPath));
    
    // 워커 스레드에서 복호화 실행 (시그널 사용)
    emit worker->processFileListRequested(filePairs, false, 0, password);
}

void MainWindow::onProgressUpdated(qint64 processed, qint64 total, const QString &fileName)
{
    // total이 0이거나 음수인 경우 처리
    if (total <= 0) {
        ui->progressBar->setValue(0);
        ui->statusLabel->setText(QString("Processing %1...").arg(QFileInfo(fileName).fileName()));
        return;
    }
    
    // processed가 음수이거나 total보다 큰 경우 처리
    if (processed < 0) {
        processed = 0;
    }
    if (processed > total) {
        processed = total;
    }
    
    // 진행률 계산 (오버플로우 방지를 위해 64비트로 계산)
    qint64 percent = (processed * 100) / total;
    if (percent > 100) percent = 100;
    if (percent < 0) percent = 0;
    
    ui->progressBar->setValue(static_cast<int>(percent));
    ui->statusLabel->setText(QString("Processing %1: %2 / %3 bytes (%4%)")
                            .arg(QFileInfo(fileName).fileName())
                            .arg(processed).arg(total).arg(percent));
}

void MainWindow::onFinished(bool success, const QString &message)
{
    ui->progressBar->setValue(100);
    ui->statusLabel->setText(message);
    enableButtons(true);
    
    if (success) {
        QMessageBox::information(this, "Success", message);
        
        // 성공한 경우 처리된 파일만 리스트에서 제거
        if (processingFileIndex >= 0 && processingFileIndex < fileList.size()) {
            fileList.removeAt(processingFileIndex);
            updateFileListDisplay();
            
            // 선택 해제 및 다음 파일 선택
            if (ui->fileListWidget->count() > 0) {
                if (processingFileIndex < ui->fileListWidget->count()) {
                    ui->fileListWidget->setCurrentRow(processingFileIndex);
                } else if (ui->fileListWidget->count() > 0) {
                    ui->fileListWidget->setCurrentRow(ui->fileListWidget->count() - 1);
                }
            }
            updateOutputPathForCurrentFile();
        }
    } else {
        QMessageBox::warning(this, "Warning", message);
    }
    
    // UI 요소만 초기화 (파일 리스트는 유지)
    ui->passwordEdit->clear();
    ui->outputPathEdit->clear();
    ui->progressBar->setValue(0);
    
    processingFileIndex = -1;
}

void MainWindow::onError(const QString &errorMessage)
{
    ui->statusLabel->setText(errorMessage);
    enableButtons(true);
    QMessageBox::critical(this, "Error", errorMessage);
    
    // UI 요소만 초기화 (파일 리스트는 유지)
    ui->passwordEdit->clear();
    ui->outputPathEdit->clear();
    ui->progressBar->setValue(0);
    
    processingFileIndex = -1;
}

void MainWindow::resetUI()
{
    // 파일 리스트 초기화
    fileList.clear();
    ui->fileListWidget->clear();
    
    // 패스워드 입력창 초기화
    ui->passwordEdit->clear();
    
    // 출력 경로 입력창 초기화
    ui->outputPathEdit->clear();
    
    // 진행률 바 초기화
    ui->progressBar->setValue(0);
    
    // 상태 레이블 초기화
    ui->statusLabel->setText("Ready");
    
    // AES 키 길이 기본값으로 설정
    ui->aes128Radio->setChecked(true);
}
