#include <gtest/gtest.h>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstring>

#include "core/pe/PEParser.h"

namespace {

QString writePeFile(const QDir &dir,
                    const QString &fileName,
                    bool is64Bit,
                    quint32 entryPointRva,
                    const QByteArray &sectionName,
                    quint32 sectionRva,
                    quint32 sectionSize)
{
    const QString path = dir.filePath(fileName);
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        ADD_FAILURE() << "Failed to open temporary PE file";
        return QString();
    }

    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = sizeof(IMAGE_DOS_HEADER) + 0x20; // leave some padding
    file.write(reinterpret_cast<const char *>(&dos), sizeof(dos));

    const QByteArray padding(dos.e_lfanew - sizeof(IMAGE_DOS_HEADER), '\0');
    file.write(padding);

    const quint32 signature = IMAGE_NT_SIGNATURE;
    file.write(reinterpret_cast<const char *>(&signature), sizeof(signature));

    IMAGE_FILE_HEADER fileHeader{};
    fileHeader.Machine = is64Bit ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    fileHeader.NumberOfSections = 1;
    fileHeader.SizeOfOptionalHeader = is64Bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
    file.write(reinterpret_cast<const char *>(&fileHeader), sizeof(fileHeader));

    if (is64Bit) {
        IMAGE_OPTIONAL_HEADER64 optional{};
        optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optional.AddressOfEntryPoint = entryPointRva;
        optional.SectionAlignment = 0x1000;
        optional.FileAlignment = 0x200;
        file.write(reinterpret_cast<const char *>(&optional), sizeof(optional));
    } else {
        IMAGE_OPTIONAL_HEADER32 optional{};
        optional.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        optional.AddressOfEntryPoint = entryPointRva;
        optional.SectionAlignment = 0x1000;
        optional.FileAlignment = 0x200;
        file.write(reinterpret_cast<const char *>(&optional), sizeof(optional));
    }

    IMAGE_SECTION_HEADER section{};
    std::memset(section.Name, 0, sizeof(section.Name));
    const QByteArray truncated = sectionName.left(sizeof(section.Name));
    std::memcpy(section.Name, truncated.constData(), truncated.size());
    section.Misc.VirtualSize = sectionSize;
    section.VirtualAddress = sectionRva;
    section.SizeOfRawData = sectionSize;
    file.write(reinterpret_cast<const char *>(&section), sizeof(section));

    file.close();
    return path;
}

} // namespace

TEST(PeParserTests, ParsesValid64BitPe)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());

    const QString path = writePeFile(QDir(dir.path()), QStringLiteral("valid64.exe"), true, 0x1234, ".text", 0x1000, 0x200);
    ASSERT_FALSE(path.isEmpty());

    core::PEParser parser;
    const auto info = parser.parse(path);
    ASSERT_TRUE(info.has_value());
    EXPECT_TRUE(info->is64Bit);
    EXPECT_EQ(info->numberOfSections, 1u);
    EXPECT_EQ(info->entryPointRva, 0x1234u);
    ASSERT_EQ(info->sections.size(), 1u);
    EXPECT_EQ(info->sections[0].name, QStringLiteral(".text"));
    EXPECT_EQ(info->sections[0].virtualAddress, 0x1000u);
    EXPECT_EQ(info->sections[0].size, 0x200u);
}

TEST(PeParserTests, ReturnsNulloptWhenFileMissing)
{
    core::PEParser parser;
    const auto info = parser.parse(QStringLiteral("Z:/nonexistent/file.exe"));
    EXPECT_FALSE(info.has_value());
}

TEST(PeParserTests, RejectsCorruptedPeSignature)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());

    const QString path = dir.filePath(QStringLiteral("broken.exe"));
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));

    IMAGE_DOS_HEADER dos{};
    dos.e_magic = 0; // invalid
    file.write(reinterpret_cast<const char *>(&dos), sizeof(dos));
    file.close();

    core::PEParser parser;
    const auto info = parser.parse(path);
    EXPECT_FALSE(info.has_value());
}
