#pragma once

#include <QMainWindow>
#include <QString>
#include <memory>

#include "core/util/SettingsManager.h"

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
    void onOpenSettings();

private:
    void setupUi();
    void connectSignals();
    void applySettingsToAuthClient();

    std::unique_ptr<MainWindowUi> ui_;
    std::unique_ptr<core::ProtectionPassManager> passManager_;
    std::unique_ptr<core::AuthClient> authClient_;
    core::SettingsManager settingsManager_;
    QString targetFilePath_;
};
