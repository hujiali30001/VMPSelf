#pragma execution_character_set("utf-8")

#include "app/MainWindow.h"

#include "app/SettingsDialog.h"

#include <QAction>
#include <QFileDialog>
#include <QFileInfo>
#include <QMenuBar>
#include <QMessageBox>
#include <QStatusBar>
#include <QTextEdit>
#include <QToolBar>
#include <QVBoxLayout>

#include "core/auth/AuthClient.h"
#include "core/pe/PEParser.h"
#include "core/pipeline/ProtectionPassManager.h"
#include "core/util/Logger.h"
#include "core/util/SettingsManager.h"

namespace {
constexpr auto WINDOW_TITLE = "VMP Self Protector";
}

class MainWindowUi
{
public:
    QWidget *centralWidget = nullptr;
    QTextEdit *logView = nullptr;
    QAction *openFileAction = nullptr;
    QAction *buildAction = nullptr;
    QAction *testAuthAction = nullptr;
    QAction *settingsAction = nullptr;
};

MainWindow::MainWindow(QWidget *parent)
        : QMainWindow(parent),
            ui_(std::make_unique<MainWindowUi>()),
            passManager_(std::make_unique<core::ProtectionPassManager>()),
            authClient_(std::make_unique<core::AuthClient>())
{
    setupUi();
    core::Logger::instance().setSink([this](const QString &message) {
        if (ui_->logView) {
            ui_->logView->append(message);
        }
    });
    connectSignals();
    settingsManager_.load();
    applySettingsToAuthClient();
    core::Logger::instance().log("Main window initialized");
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUi()
{
    setWindowTitle(WINDOW_TITLE);
    resize(960, 600);

    auto *central = new QWidget(this);
    auto *layout = new QVBoxLayout(central);
    ui_->logView = new QTextEdit(central);
    ui_->logView->setReadOnly(true);
    layout->addWidget(ui_->logView);

    setCentralWidget(central);

    ui_->openFileAction = new QAction(tr("打开目标程序"), this);
    ui_->buildAction = new QAction(tr("生成保护"), this);
    ui_->testAuthAction = new QAction(tr("测试授权"), this);
    ui_->settingsAction = new QAction(tr("授权配置"), this);

    auto *fileMenu = menuBar()->addMenu(tr("文件"));
    fileMenu->addAction(ui_->openFileAction);
    fileMenu->addAction(ui_->settingsAction);

    auto *protectMenu = menuBar()->addMenu(tr("保护"));
    protectMenu->addAction(ui_->buildAction);
    protectMenu->addAction(ui_->testAuthAction);

    auto *toolBar = addToolBar(tr("工具"));
    toolBar->addAction(ui_->openFileAction);
    toolBar->addAction(ui_->buildAction);
    toolBar->addAction(ui_->testAuthAction);
    toolBar->addAction(ui_->settingsAction);
}

void MainWindow::connectSignals()
{
    connect(ui_->openFileAction, &QAction::triggered, this, &MainWindow::onOpenFile);
    connect(ui_->buildAction, &QAction::triggered, this, &MainWindow::onBuildProtection);
    connect(ui_->testAuthAction, &QAction::triggered, this, &MainWindow::onTestActivation);
    connect(ui_->settingsAction, &QAction::triggered, this, &MainWindow::onOpenSettings);
}

void MainWindow::onOpenFile()
{
    const QString startDir = settingsManager_.lastTargetPath();
    const QString filePath = QFileDialog::getOpenFileName(this,
                                                          tr("选择可执行文件"),
                                                          startDir,
                                                          tr("Executable Files (*.exe)"));
    if (filePath.isEmpty()) {
        return;
    }

    targetFilePath_ = filePath;
    settingsManager_.setLastTargetPath(QFileInfo(filePath).absolutePath());
    settingsManager_.save();
    statusBar()->showMessage(tr("选择文件: %1").arg(filePath));
    core::Logger::instance().log(QString("Loaded target program: %1").arg(filePath));

    core::PEParser parser;
    auto info = parser.parse(filePath);
    if (!info) {
        QMessageBox::warning(this, tr("PE 解析"), tr("无法解析所选文件的 PE 信息，请查看日志。"));
        return;
    }

    const QString arch = info->is64Bit ? tr("x64") : tr("x86");
    core::Logger::instance().log(tr("PE 信息 -> 架构: %1, 节数: %2, 入口 RVA: 0x%3")
                                     .arg(arch)
                                     .arg(info->numberOfSections)
                                     .arg(QString::number(info->entryPointRva, 16).rightJustified(8, QLatin1Char('0')).toUpper()));

    for (const auto &section : info->sections) {
        const QString name = section.name.isEmpty() ? tr("<未命名>") : section.name;
        const QString line = tr("   节 %1 : RVA 0x%2, 大小 0x%3")
                                 .arg(name, -8)
                                 .arg(QString::number(section.virtualAddress, 16).toUpper())
                                 .arg(QString::number(section.size, 16).toUpper());
        core::Logger::instance().log(line);
    }
}

void MainWindow::onBuildProtection()
{
    if (targetFilePath_.isEmpty()) {
        QMessageBox::warning(this, tr("提示"), tr("请先选择待保护的程序。"));
        return;
    }

    const QString outputPath = targetFilePath_ + ".protected";
    const bool ok = passManager_->run(targetFilePath_, outputPath);
    if (ok) {
        QString detail = tr("已完成占位保护流程，输出: %1").arg(outputPath);
        if (const auto *ctx = passManager_->lastContext()) {
            if (ctx->peInfo) {
                detail += tr("\n架构: %1, 节数: %2, 入口 RVA: 0x%3")
                              .arg(ctx->peInfo->is64Bit ? tr("x64") : tr("x86"))
                              .arg(ctx->peInfo->numberOfSections)
                              .arg(QString::number(ctx->peInfo->entryPointRva, 16).toUpper());
            }
        }
        const auto &results = passManager_->lastResults();
        if (!results.empty()) {
            detail += tr("\n\n执行详情:");
            for (const auto &record : results) {
                detail += tr("\n - %1: %2 ms")
                              .arg(record.name)
                              .arg(record.durationMs);
            }
        }
        QMessageBox::information(this, tr("提示"), detail);
    } else {
        QMessageBox::critical(this, tr("提示"), tr("保护流程失败，请查看日志。"));
    }
}

void MainWindow::onTestActivation()
{
    if (!authClient_->config()) {
        QMessageBox::information(this, tr("授权测试"), tr("请先在“授权配置”中设置服务器信息。"));
        return;
    }

    core::Logger::instance().log("Running activation test (stub)");
    const auto result = authClient_->testConnection();
    if (result) {
        QMessageBox::information(this, tr("授权测试"), tr("连接成功。"));
    } else {
        QMessageBox::warning(this, tr("授权测试"), tr("连接失败，请检查配置。"));
    }
}

void MainWindow::onOpenSettings()
{
    SettingsDialog dialog(settingsManager_.authSettings(), this);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    settingsManager_.setAuthSettings(dialog.authSettings());
    if (!settingsManager_.save()) {
        QMessageBox::warning(this, tr("授权配置"), tr("保存配置文件失败，请检查写入权限。"));
        return;
    }

    applySettingsToAuthClient();

    QMessageBox::information(this, tr("授权配置"), tr("配置已保存。"));
}

void MainWindow::applySettingsToAuthClient()
{
    const auto config = settingsManager_.authClientConfig();
    if (config) {
        authClient_->setConfig(*config);
        core::Logger::instance().log(QStringLiteral("AuthClient: 已配置服务器 %1").arg(config->baseUrl.toString()));
    } else {
        core::Logger::instance().log(QStringLiteral("AuthClient: 配置信息不完整，等待用户输入"));
    }
}
