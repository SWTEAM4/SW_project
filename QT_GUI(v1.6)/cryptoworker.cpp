#include "cryptoworker.h"
#include <QDebug>
#include <QByteArray>
#include <QFileInfo>
#include <QDir>

CryptoWorker::CryptoWorker(QObject *parent)
    : QObject(parent)
{
}

// C 콜백을 Qt 시그널로 변환
void CryptoWorker::progressCallback(long processed, long total, void *userData)
{
    CryptoWorker *worker = static_cast<CryptoWorker*>(userData);
    if (worker && total > 0 && processed >= 0) {
        // long을 qint64로 변환 (오버플로우 방지)
        // Qt의 시그널/슬롯은 스레드 안전하므로 직접 emit 가능
        emit worker->progressUpdated(static_cast<qint64>(processed), static_cast<qint64>(total), worker->currentFileName);
    }
}

// 경로 변환 유틸리티 함수 구현
QByteArray CryptoWorker::toNativePathBytes(const QString &path)
{
    return QDir::toNativeSeparators(path).toUtf8();
}

// 암호화 공통 로직
bool CryptoWorker::performEncryption(const QString &inputPath, const QString &outputPath, 
                                     int aesKeyBits, const QString &password)
{
    // 경로를 네이티브 형식으로 변환 후 UTF-8 바이트 배열로 변환
    QByteArray inputBytes = toNativePathBytes(inputPath);
    QByteArray outputBytes = toNativePathBytes(outputPath);
    QByteArray passwordBytes = password.toUtf8();
    
    currentFileName = inputPath;
    
    // 암호화 실행 (콜백 전달)
    int result = encrypt_file_with_progress(
        inputBytes.constData(),
        outputBytes.constData(),
        aesKeyBits,
        passwordBytes.constData(),
        progressCallback,
        this  // user_data로 this 전달
    );
    
    return (result != 0);
}

// 복호화 공통 로직
bool CryptoWorker::performDecryption(const QString &inputPath, const QString &outputPath,
                                     const QString &password)
{
    // 경로를 네이티브 형식으로 변환 후 UTF-8 바이트 배열로 변환
    QByteArray inputBytes = toNativePathBytes(inputPath);
    QByteArray outputBytes = toNativePathBytes(outputPath);
    QByteArray passwordBytes = password.toUtf8();
    
    char finalPath[512];
    memset(finalPath, 0, sizeof(finalPath));  // 초기화
    
    currentFileName = inputPath;
    
    int result = decrypt_file_with_progress(
        inputBytes.constData(),
        outputBytes.constData(),
        passwordBytes.constData(),
        finalPath,
        sizeof(finalPath),
        progressCallback,
        this
    );
    
    return (result != 0);
}

void CryptoWorker::processFileList(const QList<QPair<QString, QString>> &fileList,
                                   bool isEncrypt, int aesKeyBits, const QString &password)
{
    int successCount = 0;
    int failCount = 0;
    QStringList successFiles;
    QStringList failFiles;
    
    for (int i = 0; i < fileList.size(); ++i) {
        const QPair<QString, QString> &filePair = fileList[i];
        QString inputPath = filePair.first;
        QString outputPath = filePair.second;
        
        bool success = false;
        
        if (isEncrypt) {
            success = performEncryption(inputPath, outputPath, aesKeyBits, password);
        } else {
            // Windows 네이티브 경로로 변환 (구분자 통일) - 검증용
            QString nativeInputPath = QDir::toNativeSeparators(inputPath);
            QString nativeOutputPath = QDir::toNativeSeparators(outputPath);
            
            // 디버그 로그 추가
            qDebug() << "Decrypting file:";
            qDebug() << "  Input path:" << nativeInputPath;
            qDebug() << "  Output path:" << nativeOutputPath;
            
            // 입력 파일 존재 여부 확인
            QFileInfo inputInfo(nativeInputPath);
            if (!inputInfo.exists() || !inputInfo.isFile()) {
                QString errorMsg = QString("Input file does not exist or is not a file: %1").arg(nativeInputPath);
                qDebug() << "Error:" << errorMsg;
                emit error(errorMsg);
                failCount++;
                failFiles.append(QFileInfo(inputPath).fileName());
                continue;
            }
            
            // 출력 경로 유효성 검사
            QFileInfo outputInfo(nativeOutputPath);
            QDir outputDir = outputInfo.absoluteDir();
            if (!outputDir.exists()) {
                QString errorMsg = QString("Output directory does not exist: %1").arg(outputDir.absolutePath());
                qDebug() << "Error:" << errorMsg;
                emit error(errorMsg);
                failCount++;
                failFiles.append(QFileInfo(inputPath).fileName());
                continue;
            }
            
            // 복호화 실행
            success = performDecryption(inputPath, outputPath, password);
            
            if (!success) {
                // 복호화 실패 시 구체적인 에러 메시지 emit
                QString errorMsg = QString(
                    "Decryption failed: %1\n\nPossible causes:\n"
                    "- Wrong password\n- File is corrupted\n"
                    "- Invalid file format (not a .enc file)\n"
                    "- Output path not writable")
                    .arg(QFileInfo(inputPath).fileName());
                qDebug() << "Decryption error:" << errorMsg;
                emit error(errorMsg);
            }
        }
        
        if (success) {
            successCount++;
            successFiles.append(QFileInfo(inputPath).fileName());
        } else {
            failCount++;
            failFiles.append(QFileInfo(inputPath).fileName());
        }
    }
    
    // 결과 메시지 생성
    QString message;
    if (fileList.size() == 1) {
        if (successCount > 0) {
            message = QString("%1 completed successfully!")
                .arg(isEncrypt ? "Encryption" : "Decryption");
        } else {
            message = QString("%1 failed!")
                .arg(isEncrypt ? "Encryption" : "Decryption");
        }
    } else {
        message = QString("%1 completed: %2 success, %3 failed")
            .arg(isEncrypt ? "Encryption" : "Decryption")
            .arg(successCount)
            .arg(failCount);
        
        if (failCount > 0) {
            message += "\nFailed files: " + failFiles.join(", ");
        }
    }
    
    emit finished(successCount > 0, message);
}
