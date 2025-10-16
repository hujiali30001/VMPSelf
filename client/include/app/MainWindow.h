#pragma once

#include <QMainWindow>
#include <QString>
#include <memory>

class MainWindowUi;

namespace core {
class ProtectionPassManager;
class AuthClient;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void onOpenFile();
    void onBuildProtection();
    void onTestActivation();

private:
    void setupUi();
    void connectSignals();

    std::unique_ptr<MainWindowUi> ui_;
    std::unique_ptr<core::ProtectionPassManager> passManager_;
    std::unique_ptr<core::AuthClient> authClient_;
    QString targetFilePath_;
};
