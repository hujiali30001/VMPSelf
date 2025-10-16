#include "core/pipeline/ProtectionPassManager.h"

#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>

#include "core/util/Logger.h"

namespace core {

namespace {

class PEAnalysisPass : public ProtectionPass
{
public:
    QString name() const override { return QStringLiteral("PEAnalysis"); }

    bool execute(ProtectionContext &context) override
    {
        if (context.peInfo) {
            Logger::instance().log(QStringLiteral("PEAnalysis: 已存在解析结果，跳过"));
            return true;
        }

        PEParser parser;
        auto info = parser.parse(context.inputPath);
        if (!info) {
            Logger::instance().log(QStringLiteral("PEAnalysis: 解析失败"));
            return false;
        }

        context.peInfo = *info;
        const QString arch = info->is64Bit ? QStringLiteral("x64") : QStringLiteral("x86");
        Logger::instance().log(QStringLiteral("PEAnalysis: 架构=%1, 节数=%2, 入口RVA=0x%3")
                                   .arg(arch)
                                   .arg(info->numberOfSections)
                                   .arg(QString::number(info->entryPointRva, 16).toUpper()));
        return true;
    }
};

class FileClonePass : public ProtectionPass
{
public:
    QString name() const override { return QStringLiteral("FileClone"); }

    bool execute(ProtectionContext &context) override
    {
        const QFileInfo inputInfo(context.inputPath);
        if (!inputInfo.exists()) {
            Logger::instance().log(QStringLiteral("FileClone: 输入文件不存在"));
            return false;
        }

        QDir outputDir = QFileInfo(context.outputPath).dir();
        if (!outputDir.exists() && !outputDir.mkpath(QStringLiteral("."))) {
            Logger::instance().log(QStringLiteral("FileClone: 创建输出目录失败 -> %1").arg(outputDir.absolutePath()));
            return false;
        }

        if (QFile::exists(context.outputPath) && !QFile::remove(context.outputPath)) {
            Logger::instance().log(QStringLiteral("FileClone: 无法移除已有输出文件"));
            return false;
        }

        if (!QFile::copy(context.inputPath, context.outputPath)) {
            Logger::instance().log(QStringLiteral("FileClone: 复制文件失败"));
            return false;
        }

        Logger::instance().log(QStringLiteral("FileClone: 已复制到 %1").arg(context.outputPath));
        return true;
    }
};

} // namespace

ProtectionPassManager::ProtectionPassManager()
{
    addPass(std::make_unique<PEAnalysisPass>());
    addPass(std::make_unique<FileClonePass>());
}

ProtectionPassManager::~ProtectionPassManager() = default;

void ProtectionPassManager::addPass(std::unique_ptr<ProtectionPass> pass)
{
    passes_.push_back(std::move(pass));
}

bool ProtectionPassManager::run(const QString &inputPath, const QString &outputPath)
{
    ProtectionContext context{inputPath, outputPath, std::nullopt};

    lastResults_.clear();

    for (auto &pass : passes_) {
        Logger::instance().log(QStringLiteral("开始执行 Pass: %1").arg(pass->name()));
        QElapsedTimer timer;
        timer.start();
        const bool success = pass->execute(context);
        const qint64 duration = timer.elapsed();

        lastResults_.push_back(PassExecutionResult{pass->name(), success, duration});

        if (!success) {
            Logger::instance().log(QStringLiteral("Pass '%1' 执行失败，用时 %2 ms")
                                       .arg(pass->name())
                                       .arg(duration));
            return false;
        }

        Logger::instance().log(QStringLiteral("Pass '%1' 完成，用时 %2 ms")
                                   .arg(pass->name())
                                   .arg(duration));
    }

    lastContext_ = context;
    Logger::instance().log(QStringLiteral("Protection pipeline completed"));
    return true;
}

const ProtectionContext *ProtectionPassManager::lastContext() const
{
    return lastContext_ ? &*lastContext_ : nullptr;
}

const std::vector<PassExecutionResult> &ProtectionPassManager::lastResults() const
{
    return lastResults_;
}

} // namespace core
