#ifndef CRYPTOWORKER_H
#define CRYPTOWORKER_H

#include <QObject>
#include <QString>
#include <QPair>
#include <QList>
#include "file_crypto.h"

class CryptoWorker : public QObject
{
    Q_OBJECT

public:
    explicit CryptoWorker(QObject *parent = nullptr);

public slots:
    void encryptFile(const QString &inputPath, const QString &outputPath,
                     int aesKeyBits, const QString &password);
    void decryptFile(const QString &inputPath, const QString &outputPath,
                     const QString &password);
    void processFileList(const QList<QPair<QString, QString>> &fileList,
                         bool isEncrypt, int aesKeyBits, const QString &password);

signals:
    void progressUpdated(qint64 processed, qint64 total, const QString &fileName);
    void finished(bool success, const QString &message);
    void error(const QString &errorMessage);
    void processFileListRequested(const QList<QPair<QString, QString>> &fileList,
                                  bool isEncrypt, int aesKeyBits, const QString &password);

private:
    QString currentFileName;  // 현재 처리 중인 파일명 (진행률 표시용)
    
    // C 콜백을 Qt 시그널로 변환하는 정적 함수
    static void progressCallback(long processed, long total, void *userData);
};

#endif // CRYPTOWORKER_H

