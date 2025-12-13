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
    // 공통 UI 상태 초기화
    resetUIState();
    
    // 버튼 연결
    connect(ui->selectFilesButton, &QPushButton::clicked, this, &MainWindow::onSelectFiles);
    connect(ui->removeFileButton, &QPushButton::clicked, this, &MainWindow::onRemoveFile);
    connect(ui->browseOutputButton, &QPushButton::clicked, this, &MainWindow::onBrowseOutputPath);
    connect(ui->outputPathEdit, &QLineEdit::textChanged, this, &MainWindow::onOutputPathChanged);
    connect(ui->fileListWidget, &QListWidget::itemSelectionChanged, 
            this, &MainWindow::onFileListSelectionChanged);
    connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::onEncrypt);
    connect(ui->decryptButton, &QPushButton::clicked, this, &MainWindow::onDecrypt);
    
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
    QStringList files = QFileDialog::getOpenFileNames(this, DialogTitles::SELECT_FILES);
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
            fileInfo.isEncrypted = isEncryptedFile(filePath);
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
        showInfo(ErrorMessages::SELECT_FILE_TO_REMOVE);
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
    QByteArray inputBytes = toNativePathBytes(inputPath);

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
    QString baseName = removeEncExtension(inputInfo.completeBaseName());

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
        suggested += FileExtensions::BIN;
    }
    return suggested;
}

void MainWindow::onBrowseOutputPath()
{
    QListWidgetItem *item = ui->fileListWidget->currentItem();
    if (!item) {
        showInfo(ErrorMessages::SELECT_FILE_FIRST);
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
            QString baseName = removeEncExtension(inputInfo.completeBaseName());
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
        filter = FileFilters::ENCRYPTED_FILES;
    } else {
        QString ext = QFileInfo(defaultPath).suffix();
        if (!ext.isEmpty()) {
            filter = QString(FileFilters::RECOVERED_FILES_TEMPLATE).arg(ext);
        } else {
            filter = FileFilters::RECOVERED_FILES_BIN;
        }
    }

    QString filePath = QFileDialog::getSaveFileName(this,
        isEncryptMode ? DialogTitles::SAVE_ENCRYPTED_FILE : DialogTitles::SAVE_DECRYPTED_FILE,
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

// .enc 확장자 처리 유틸리티 함수 구현
bool MainWindow::isEncryptedFile(const QString &filePath)
{
    return filePath.endsWith(".enc", Qt::CaseInsensitive);
}

QString MainWindow::removeEncExtension(const QString &baseName)
{
    QString result = baseName;
    if (result.endsWith(".enc", Qt::CaseInsensitive)) {
        result.chop(4);  // ".enc" 제거
    }
    return result;
}

QString MainWindow::addEncExtension(const QString &baseName)
{
    if (baseName.endsWith(".enc", Qt::CaseInsensitive)) {
        return baseName;  // 이미 .enc가 있으면 그대로 반환
    }
    return baseName + ".enc";
}

QString MainWindow::generateDefaultOutputPath(const QString &inputPath, bool isEncrypt) const
{
    QFileInfo fileInfo(inputPath);
    QString separator = QDir::separator();
    
    if (isEncrypt) {
        return fileInfo.path() + separator + addEncExtension(fileInfo.completeBaseName());
    } else {
        // 복호화: 확장자 없이 경로만 반환
        // 복호화 함수가 헤더에서 읽은 원본 확장자를 자동으로 추가함
        QString baseName = removeEncExtension(fileInfo.completeBaseName());
        // 확장자 없이 경로만 반환 (복호화 함수가 헤더에서 읽은 원본 확장자를 추가)
        return fileInfo.path() + separator + baseName;
    }
}

// 파일 선택 검증 (onEncrypt와 onDecrypt에서 공통 사용)
int MainWindow::getSelectedFileIndex() const
{
    QListWidgetItem *item = ui->fileListWidget->currentItem();
    if (!item) {
        return -1;
    }
    
    int index = ui->fileListWidget->row(item);
    if (index < 0 || index >= fileList.size()) {
        return -1;
    }
    
    return index;
}

// 확장자 정규화
QString MainWindow::normalizeExtension(const QString &ext)
{
    if (ext.startsWith('.')) {
        return ext;
    }
    return "." + ext;
}

// 경로 변환 유틸리티 함수 구현
QString MainWindow::toNativePath(const QString &path)
{
    return QDir::toNativeSeparators(path);
}

QByteArray MainWindow::toNativePathBytes(const QString &path)
{
    return toNativePath(path).toUtf8();
}

// 에러 메시지 표시 헬퍼 함수 구현
void MainWindow::showError(const QString &message)
{
    QMessageBox::warning(this, MessageBoxTitles::ERROR_TITLE, message);
}

void MainWindow::showCriticalError(const QString &message)
{
    QMessageBox::critical(this, MessageBoxTitles::ERROR_TITLE, message);
}

void MainWindow::showWarning(const QString &message)
{
    QMessageBox::warning(this, MessageBoxTitles::WARNING, message);
}

void MainWindow::showSuccess(const QString &message)
{
    QMessageBox::information(this, MessageBoxTitles::SUCCESS, message);
}

void MainWindow::showInfo(const QString &message)
{
    QMessageBox::information(this, MessageBoxTitles::INFO, message);
}

// 공통 UI 상태 초기화
void MainWindow::resetUIState()
{
    // 진행률 바 초기화
    ui->progressBar->setMinimum(0);
    ui->progressBar->setMaximum(100);
    ui->progressBar->setValue(0);
    
    // 상태 레이블 초기화
    ui->statusLabel->setText(StatusMessages::READY);
    
    // AES 키 길이 기본값
    ui->aes128Radio->setChecked(true);
}

// 선택된 AES 키 길이 반환
int MainWindow::getSelectedAesKeyBits() const
{
    if (ui->aes192Radio->isChecked()) {
        return 192;
    } else if (ui->aes256Radio->isChecked()) {
        return 256;
    }
    // 기본값: AES-128
    return 128;
}

// 자동 경로 결정 (헤더 읽기)
QString MainWindow::resolveAutoDecryptOutputPath(int index) const
{
    QFileInfo fileInfo(fileList[index].inputPath);
    QString baseName = removeEncExtension(fileInfo.completeBaseName());
    
    // readExtensionFromHeader() 재사용
    QString extension = readExtensionFromHeader(fileList[index].inputPath);
    
    if (!extension.isEmpty()) {
        return fileInfo.path() + QDir::separator() + baseName + extension;
    } else {
        return fileInfo.path() + QDir::separator() + baseName;
    }
}

// 사용자 입력 경로 결정
QString MainWindow::resolveUserDecryptOutputPath(int index, const QString &userPath) const
{
    QFileInfo pathInfo(userPath);
    QString baseName = pathInfo.completeBaseName();
    
    // readExtensionFromHeader() 재사용
    QString originalExt = readExtensionFromHeader(fileList[index].inputPath);
    
    if (!originalExt.isEmpty()) {
        originalExt = normalizeExtension(originalExt);
        return pathInfo.path() + QDir::separator() + baseName + originalExt;
    } else {
        return userPath;
    }
}

// 복호화 출력 경로 결정
void MainWindow::resolveDecryptOutputPath(int index)
{
    QString userPath = fileList[index].outputPath;
    QString autoPath = generateDefaultOutputPath(fileList[index].inputPath, false);
    
    // 경로 정규화하여 비교 (구분자 통일)
    QString normalizedUserPath = toNativePath(userPath);
    QString normalizedAutoPath = toNativePath(autoPath);
    
    if (userPath.isEmpty() || normalizedUserPath == normalizedAutoPath) {
        // 자동 경로: 헤더에서 확장자를 읽어서 추가
        fileList[index].outputPath = resolveAutoDecryptOutputPath(index);
    } else {
        // 사용자가 직접 입력한 경로: 헤더에서 읽은 원본 확장자로 설정
        fileList[index].outputPath = resolveUserDecryptOutputPath(index, userPath);
    }
}

void MainWindow::updateFileListDisplay()
{
    ui->fileListWidget->clear();
    
    for (int i = 0; i < fileList.size(); ++i) {
        const FileInfo &fi = fileList[i];
        QFileInfo fileInfo(fi.inputPath);
        
        // 입력 파일명: 경로에서 직접 추출 (Windows와 macOS 모두 호환)
        QString inputFileName;
        if (fi.inputPath.contains('/')) {
            inputFileName = fi.inputPath.split('/').last();
        } else if (fi.inputPath.contains('\\')) {
            inputFileName = fi.inputPath.split('\\').last();
        } else {
            inputFileName = fileInfo.fileName();
        }
        
        if (inputFileName.isEmpty()) {
            inputFileName = fileInfo.fileName();
        }
        
        // 출력 파일명 표시
        QString outputFileName;
        if (fi.isEncrypted) {
            // .enc 파일인 경우: 헤더에서 원본 확장자 읽어서 표시
            QString originalExt = readExtensionFromHeader(fi.inputPath);
            if (!originalExt.isEmpty()) {
                // 입력 파일명에서 .enc 제거하여 baseName 추출
                QString baseName = removeEncExtension(inputFileName);
                // 확장자가 .으로 시작하지 않으면 추가
                if (!originalExt.startsWith('.')) {
                    originalExt = "." + originalExt;
                }
                outputFileName = baseName + originalExt;
            } else {
                // 확장자를 찾을 수 없으면 .bin으로 표시
                QString baseName = removeEncExtension(inputFileName);
                outputFileName = baseName + FileExtensions::BIN;
            }
        } else {
        // 일반 파일인 경우: .enc 확장자로 표시
        QFileInfo outputInfo(fi.outputPath);
        if (outputInfo.suffix().toLower() == "enc") {
            outputFileName = outputInfo.fileName();
        } else {
            // .enc가 없으면 추가
            outputFileName = addEncExtension(outputInfo.completeBaseName());
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
    
    // 파일 선택 검증
    int index = getSelectedFileIndex();
    if (index < 0) {
        showError(ErrorMessages::SELECT_FILE_TO_ENCRYPT);
        return;
    }
    
    // 처리 중인 파일 인덱스 저장
    processingFileIndex = index;
    
    QString password = ui->passwordEdit->text();
    if (password.isEmpty()) {
        showError(ErrorMessages::ENTER_PASSWORD);
        return;
    }
    
    // 패스워드 검증
    QByteArray passwordBytes = password.toUtf8();
    if (!validate_password(passwordBytes.constData())) {
        showError(ErrorMessages::PASSWORD_VALIDATION);
        return;
    }
    
    // 선택된 파일의 출력 경로 업데이트
    if (fileList[index].outputPath.isEmpty()) {
        fileList[index].outputPath = generateDefaultOutputPath(fileList[index].inputPath, true);
    }
    
    // 선택된 AES 키 길이 가져오기
    int aesKeyBits = getSelectedAesKeyBits();
    
    ui->progressBar->setValue(0);
    ui->statusLabel->setText(StatusMessages::PREPARING_ENCRYPTION);
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
    
    // 파일 선택 검증
    int index = getSelectedFileIndex();
    if (index < 0) {
        showError(ErrorMessages::SELECT_FILE_TO_DECRYPT);
        return;
    }
    
    // 처리 중인 파일 인덱스 저장
    processingFileIndex = index;
    
    // 패스워드 검증
    QString password = ui->passwordEdit->text();
    if (password.isEmpty()) {
        showError(ErrorMessages::ENTER_PASSWORD_FOR_DECRYPT);
        return;
    }
    
    // 출력 경로 결정
    resolveDecryptOutputPath(index);
    
    // UI 업데이트
    ui->progressBar->setValue(0);
    ui->statusLabel->setText(StatusMessages::PREPARING_DECRYPTION);
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
        ui->statusLabel->setText(QString(StatusMessages::PROCESSING_TEMPLATE).arg(QFileInfo(fileName).fileName()));
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
        showSuccess(message);
        
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
        showWarning(message);
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
    showCriticalError(errorMessage);
    
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
    
    // 공통 UI 상태 초기화
    resetUIState();
}
