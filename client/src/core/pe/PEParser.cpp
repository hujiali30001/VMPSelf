#pragma execution_character_set("utf-8")

#include "core/pe/PEParser.h"

#include <algorithm>

#include <QByteArray>
#include <QFile>
#include <QFileInfo>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "core/util/Logger.h"

namespace core {

namespace {

QString sectionNameFromRaw(const IMAGE_SECTION_HEADER &header)
{
	QByteArray raw(reinterpret_cast<const char *>(header.Name), sizeof(header.Name));
	const int nulIndex = raw.indexOf('\0');
	if (nulIndex >= 0) {
		raw.truncate(nulIndex);
	}
	return QString::fromLatin1(raw);
}

} // namespace

std::optional<PEInfo> PEParser::parse(const QString &path)
{
	QFileInfo fileInfo(path);
	if (!fileInfo.exists() || !fileInfo.isFile()) {
		Logger::instance().log(QStringLiteral("PEParser: 文件不存在 -> %1").arg(path));
		return std::nullopt;
	}

	QFile file(path);
	if (!file.open(QIODevice::ReadOnly)) {
		Logger::instance().log(QStringLiteral("PEParser: 无法打开文件 -> %1").arg(file.errorString()));
		return std::nullopt;
	}

	if (file.size() < static_cast<qint64>(sizeof(IMAGE_DOS_HEADER))) {
		Logger::instance().log(QStringLiteral("PEParser: 文件过小，无法读取 DOS 头"));
		return std::nullopt;
	}

	IMAGE_DOS_HEADER dosHeader{};
	if (file.read(reinterpret_cast<char *>(&dosHeader), sizeof(dosHeader)) != sizeof(dosHeader)) {
		Logger::instance().log(QStringLiteral("PEParser: 读取 DOS 头失败"));
		return std::nullopt;
	}

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		Logger::instance().log(QStringLiteral("PEParser: 非法 DOS 签名"));
		return std::nullopt;
	}

	if (!file.seek(dosHeader.e_lfanew)) {
		Logger::instance().log(QStringLiteral("PEParser: e_lfanew 越界"));
		return std::nullopt;
	}

	quint32 signature = 0;
	if (file.read(reinterpret_cast<char *>(&signature), sizeof(signature)) != sizeof(signature)) {
		Logger::instance().log(QStringLiteral("PEParser: 读取 PE 签名失败"));
		return std::nullopt;
	}

	if (signature != IMAGE_NT_SIGNATURE) {
		Logger::instance().log(QStringLiteral("PEParser: 非法 PE 签名"));
		return std::nullopt;
	}

	IMAGE_FILE_HEADER fileHeader{};
	if (file.read(reinterpret_cast<char *>(&fileHeader), sizeof(fileHeader)) != sizeof(fileHeader)) {
		Logger::instance().log(QStringLiteral("PEParser: 读取 FILE_HEADER 失败"));
		return std::nullopt;
	}

	if (fileHeader.SizeOfOptionalHeader == 0) {
		Logger::instance().log(QStringLiteral("PEParser: 可选头长度为 0"));
		return std::nullopt;
	}

	QByteArray optionalRaw = file.read(fileHeader.SizeOfOptionalHeader);
	if (optionalRaw.size() != fileHeader.SizeOfOptionalHeader) {
		Logger::instance().log(QStringLiteral("PEParser: 读取可选头失败"));
		return std::nullopt;
	}

	const auto *optionalMagic = reinterpret_cast<const quint16 *>(optionalRaw.constData());
	if (!optionalMagic) {
		Logger::instance().log(QStringLiteral("PEParser: 可选头数据无效"));
		return std::nullopt;
	}

	PEInfo info;
	info.numberOfSections = fileHeader.NumberOfSections;

	if (*optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		if (optionalRaw.size() < static_cast<int>(sizeof(IMAGE_OPTIONAL_HEADER64))) {
			Logger::instance().log(QStringLiteral("PEParser: 可选头长度不足以解析 64 位结构"));
			return std::nullopt;
		}
		const auto *optionalHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>(optionalRaw.constData());
		info.is64Bit = true;
		info.entryPointRva = optionalHeader->AddressOfEntryPoint;
	} else if (*optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		if (optionalRaw.size() < static_cast<int>(sizeof(IMAGE_OPTIONAL_HEADER32))) {
			Logger::instance().log(QStringLiteral("PEParser: 可选头长度不足以解析 32 位结构"));
			return std::nullopt;
		}
		const auto *optionalHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32 *>(optionalRaw.constData());
		info.is64Bit = false;
		info.entryPointRva = optionalHeader->AddressOfEntryPoint;
	} else {
		Logger::instance().log(QStringLiteral("PEParser: 未识别的 Optional Header Magic"));
		return std::nullopt;
	}

	const qint64 sectionTableOffset = dosHeader.e_lfanew + sizeof(quint32) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
	if (!file.seek(sectionTableOffset)) {
		Logger::instance().log(QStringLiteral("PEParser: 无法定位节表"));
		return std::nullopt;
	}

	info.sections.reserve(fileHeader.NumberOfSections);
	for (quint16 i = 0; i < fileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER sectionHeader{};
		if (file.read(reinterpret_cast<char *>(&sectionHeader), sizeof(sectionHeader)) != sizeof(sectionHeader)) {
			Logger::instance().log(QStringLiteral("PEParser: 读取节头失败 (index=%1)").arg(i));
			return std::nullopt;
		}

		SectionInfo section;
		section.name = sectionNameFromRaw(sectionHeader);
		section.virtualAddress = sectionHeader.VirtualAddress;
	const quint32 size = std::max<quint32>(sectionHeader.Misc.VirtualSize, sectionHeader.SizeOfRawData);
	section.size = size;
		info.sections.push_back(section);
	}

	Logger::instance().log(QStringLiteral("PEParser: 成功解析 %1 (节数 %2, 入口 RVA 0x%3)")
							   .arg(path)
							   .arg(info.numberOfSections)
							   .arg(QString::number(info.entryPointRva, 16)));

	return info;
}

} // namespace core
