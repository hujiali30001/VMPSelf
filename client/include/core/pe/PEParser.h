#pragma once

#include <QString>
#include <optional>
#include <vector>

namespace core {

struct SectionInfo
{
    QString name;
    quint32 virtualAddress = 0;
    quint32 size = 0;
};

struct PEInfo
{
    bool is64Bit = false;
    quint16 numberOfSections = 0;
    quint32 entryPointRva = 0;
    std::vector<SectionInfo> sections;
};

class PEParser
{
public:
    std::optional<PEInfo> parse(const QString &path);
};

} // namespace core
