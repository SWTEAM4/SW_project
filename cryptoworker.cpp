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

void CryptoWorker::encryptFile(const QString &inputPath, const QString &outputPath,
                               int aesKeyBits, const QString &password)
{
    // Windows 네이티브 경로로 변환 (구분자 통일)
    QString nativeInputPath = QDir::toNativeSeparators(inputPath);
    QString nativeOutputPath = QDir::toNativeSeparators(outputPath);
    
    // QString을 C 문자열로 변환
    QByteArray inputBytes = nativeInputPath.toUtf8();
    QByteArray outputBytes = nativeOutputPath.toUtf8();
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

    if (result) {
        emit finished(true, QString("Encryption completed: %1").arg(QFileInfo(inputPath).fileName()));
    } else {
        emit error(QString("Encryption failed: %1").arg(QFileInfo(inputPath).fileName()));
    }
}

void CryptoWorker::decryptFile(const QString &inputPath, const QString &outputPath,
                               const QString &password)
{
    // Windows 네이티브 경로로 변환 (구분자 통일)
    QString nativeInputPath = QDir::toNativeSeparators(inputPath);
    QString nativeOutputPath = QDir::toNativeSeparators(outputPath);
    
    QByteArray inputBytes = nativeInputPath.toUtf8();
    QByteArray outputBytes = nativeOutputPath.toUtf8();
    QByteArray passwordBytes = password.toUtf8();
    
    char finalPath[512];
    
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

    if (result) {
        emit finished(true, QString("Decryption completed: %1").arg(QFileInfo(inputPath).fileName()));
    } else {
        emit error(QString("Decryption failed: %1").arg(QFileInfo(inputPath).fileName()));
    }
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
            // Windows 네이티브 경로로 변환 (구분자 통일)
            QString nativeInputPath = QDir::toNativeSeparators(inputPath);
            QString nativeOutputPath = QDir::toNativeSeparators(outputPath);
            
            QByteArray inputBytes = nativeInputPath.toUtf8();
            QByteArray outputBytes = nativeOutputPath.toUtf8();
            QByteArray passwordBytes = password.toUtf8();
            
            currentFileName = inputPath;
            
            int result = encrypt_file_with_progress(
                inputBytes.constData(),
                outputBytes.constData(),
                aesKeyBits,
                passwordBytes.constData(),
                progressCallback,
                this
            );
            
            success = (result != 0);
        } else {
            // Windows 네이티브 경로로 변환 (구분자 통일)
            QString nativeInputPath = QDir::toNativeSeparators(inputPath);
            QString nativeOutputPath = QDir::toNativeSeparators(outputPath);
            
            // 디버그 로그 추가
            qDebug() << "Decrypting file:";
            qDebug() << "  Input path:" << nativeInputPath;
            qDebug() << "  Output path:" << nativeOutputPath;
            
            QByteArray inputBytes = nativeInputPath.toUtf8();
            QByteArray outputBytes = nativeOutputPath.toUtf8();
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
            
            qDebug() << "  Final path:" << QString::fromUtf8(finalPath);
            qDebug() << "  Result:" << result;
            
            if (result == 0) {
                // 복호화 실패 시 구체적인 에러 메시지 emit
                QString errorMsg = QString("Decryption failed: %1\n\nPossible causes:\n- Wrong password\n- File is corrupted\n- Invalid file format (not a .enc file)\n- Cannot create output file: %2")
                                  .arg(QFileInfo(inputPath).fileName())
                                  .arg(QString::fromUtf8(finalPath));
                qDebug() << "Decryption error:" << errorMsg;
                emit error(errorMsg);
            }
            
            success = (result != 0);
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
