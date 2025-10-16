#include <QApplication>

#include "app/MainWindow.h"
#include "core/util/Logger.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    MainWindow window;
    window.show();

    core::Logger::instance().log("Application started");
    return app.exec();
}
