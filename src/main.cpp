#include <QApplication>
#include <QFont>
#include "core/Utils.h"
#include "ui/MainWindow.h"
#include "ui/Theme.h"

int main(int argc, char* argv[])
{
    // Настройка безопасности COM должна быть выполнена до любых обращений к COM/WMI
    util::initComSecurity();

    QApplication app(argc, argv);
    QApplication::setApplicationName("SecurityChecker");
    QApplication::setStyle("Fusion");
    QApplication::setFont(QFont("Segoe UI", 10));
    app.setStyleSheet(theme::styleSheet());

    MainWindow window;
    window.show();
    return app.exec();
}
