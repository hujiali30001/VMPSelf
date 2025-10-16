#pragma once

#include <QtGlobal>
#include <QString>
#include <optional>
#include <vector>
#include <memory>

#include "core/pe/PEParser.h"

namespace core {

struct ProtectionContext
{
    QString inputPath;
    QString outputPath;
    std::optional<PEInfo> peInfo;
};

struct PassExecutionResult
{
    QString name;
    bool success = false;
    qint64 durationMs = 0;
};

class ProtectionPass
{
public:
    virtual ~ProtectionPass() = default;
    virtual QString name() const = 0;
    virtual bool execute(ProtectionContext &context) = 0;
};

class ProtectionPassManager
{
public:
    ProtectionPassManager();
    ~ProtectionPassManager();

    void addPass(std::unique_ptr<ProtectionPass> pass);
    bool run(const QString &inputPath, const QString &outputPath);
    [[nodiscard]] const ProtectionContext *lastContext() const;
    [[nodiscard]] const std::vector<PassExecutionResult> &lastResults() const;

private:
    std::vector<std::unique_ptr<ProtectionPass>> passes_;
    std::optional<ProtectionContext> lastContext_;
    std::vector<PassExecutionResult> lastResults_;
};

} // namespace core
