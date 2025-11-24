#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    app.setApplicationName("File Encryption/Decryption");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("FileCrypto");
    
    MainWindow window;
    window.show();
    
    return app.exec();
}

