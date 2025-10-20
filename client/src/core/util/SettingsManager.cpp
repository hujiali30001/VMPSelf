#include "core/util/SettingsManager.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QStandardPaths>
#include <QUrl>
#include <utility>

#include "core/util/Logger.h"

namespace core {

namespace {

QString resolveDefaultConfigPath()
{
    QString basePath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    if (basePath.isEmpty()) {
        basePath = QDir::currentPath();
    }

    QDir dir(basePath);
    return dir.filePath(QStringLiteral("vmp_shell/settings.json"));
}

bool ensureDirectoryExists(const QString &filePath)
{
    const QFileInfo info(filePath);
    QDir dir = info.dir();
    if (dir.exists()) {
        return true;
    }
    return dir.mkpath(QStringLiteral("."));
}

} // namespace

SettingsManager::SettingsManager()
    : SettingsManager(resolveDefaultConfigPath())
{
}

SettingsManager::SettingsManager(QString configFilePath)
    : configFilePath_(std::move(configFilePath))
{
    settings_.auth.baseUrl = QStringLiteral("http://192.168.132.132:11000");
    settings_.auth.cardCode = QStringLiteral("CARD-TEST");
    settings_.auth.licenseSecret = QStringLiteral("secret-key");
    settings_.auth.slotSecret.clear();
    settings_.auth.fingerprint = QStringLiteral("fp-12345");
    settings_.auth.slotCode = QStringLiteral("default-slot");
}

bool SettingsManager::load()
{
    if (configFilePath_.isEmpty()) {
        configFilePath_ = resolveDefaultConfigPath();
    }

    QFile file(configFilePath_);
    if (!file.exists()) {
        Logger::instance().log(QStringLiteral("SettingsManager: 配置文件不存在，使用默认设置"));
        return true;
    }

    if (!file.open(QIODevice::ReadOnly)) {
        Logger::instance().log(QStringLiteral("SettingsManager: 无法打开配置文件 -> %1").arg(file.errorString()));
        return false;
    }

    const QByteArray data = file.readAll();
    file.close();

    QJsonParseError parseError{};
    const QJsonDocument document = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        Logger::instance().log(QStringLiteral("SettingsManager: 配置解析失败 -> %1").arg(parseError.errorString()));
        return false;
    }

    fromJson(document.object());
    Logger::instance().log(QStringLiteral("SettingsManager: 已加载配置"));
    return true;
}

bool SettingsManager::save() const
{
    if (configFilePath_.isEmpty()) {
        Logger::instance().log(QStringLiteral("SettingsManager: 配置路径为空，无法保存"));
        return false;
    }

    if (!ensureDirectoryExists(configFilePath_)) {
        Logger::instance().log(QStringLiteral("SettingsManager: 创建配置目录失败"));
        return false;
    }

    QFile file(configFilePath_);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        Logger::instance().log(QStringLiteral("SettingsManager: 保存失败 -> %1").arg(file.errorString()));
        return false;
    }

    const QJsonDocument document(toJson());
    const QByteArray serialized = document.toJson(QJsonDocument::Indented);
    const qint64 written = file.write(serialized);
    file.close();

    if (written != serialized.size()) {
        Logger::instance().log(QStringLiteral("SettingsManager: 写入配置文件时出现错误"));
        return false;
    }

    Logger::instance().log(QStringLiteral("SettingsManager: 配置已保存"));
    return true;
}

Settings &SettingsManager::settings()
{
    return settings_;
}

const Settings &SettingsManager::settings() const
{
    return settings_;
}

void SettingsManager::setAuthSettings(const AuthSettings &authSettings)
{
    settings_.auth = authSettings;
}

AuthSettings SettingsManager::authSettings() const
{
    return settings_.auth;
}

void SettingsManager::setLastTargetPath(const QString &path)
{
    settings_.general.lastTargetPath = path;
}

QString SettingsManager::lastTargetPath() const
{
    return settings_.general.lastTargetPath;
}

std::optional<AuthClientConfig> SettingsManager::authClientConfig() const
{
    const QString baseUrlString = settings_.auth.baseUrl.trimmed();
    if (baseUrlString.isEmpty()) {
        Logger::instance().log(QStringLiteral("SettingsManager: auth config missing base_url"));
        return std::nullopt;
    }

    const QString cardCode = settings_.auth.cardCode.trimmed();
    const QString licenseSecret = settings_.auth.licenseSecret;
    const QString slotSecret = settings_.auth.slotSecret;
    const QString fingerprint = settings_.auth.fingerprint.trimmed();
    const QString slotCode = settings_.auth.slotCode.trimmed();

    if (cardCode.isEmpty() || fingerprint.isEmpty() || slotCode.isEmpty()) {
        Logger::instance().log(QStringLiteral("SettingsManager: auth config missing required identifier"));
        return std::nullopt;
    }

    if (licenseSecret.isEmpty() && slotSecret.trimmed().isEmpty()) {
        Logger::instance().log(QStringLiteral("SettingsManager: both legacy and slot secrets are empty"));
        return std::nullopt;
    }

    QUrl url = QUrl::fromUserInput(baseUrlString);
    if (!url.isValid() || url.scheme().isEmpty() || (!url.scheme().startsWith(QStringLiteral("http")))) {
        Logger::instance().log(QStringLiteral("SettingsManager: auth config URL invalid -> %1").arg(baseUrlString));
        return std::nullopt;
    }

    AuthClientConfig config;
    config.baseUrl = url;
    config.cardCode = cardCode;
    config.licenseSecret = licenseSecret;
    config.slotSecret = slotSecret.trimmed();
    config.fingerprint = fingerprint;
    config.slotCode = slotCode;
    return config;
}

QString SettingsManager::configFilePath() const
{
    return configFilePath_;
}

void SettingsManager::setConfigFilePath(const QString &path)
{
    configFilePath_ = path;
}

QString SettingsManager::defaultConfigFilePath()
{
    return resolveDefaultConfigPath();
}

void SettingsManager::fromJson(const QJsonObject &object)
{
    const QJsonObject authObject = object.value(QStringLiteral("auth")).toObject();
    if (authObject.contains(QStringLiteral("base_url"))) {
        settings_.auth.baseUrl = authObject.value(QStringLiteral("base_url")).toString();
    }
    if (authObject.contains(QStringLiteral("card_code"))) {
        settings_.auth.cardCode = authObject.value(QStringLiteral("card_code")).toString();
    }
    if (authObject.contains(QStringLiteral("license_secret"))) {
        settings_.auth.licenseSecret = authObject.value(QStringLiteral("license_secret")).toString();
    }
    if (authObject.contains(QStringLiteral("slot_secret"))) {
        settings_.auth.slotSecret = authObject.value(QStringLiteral("slot_secret")).toString();
    }
    if (authObject.contains(QStringLiteral("fingerprint"))) {
        settings_.auth.fingerprint = authObject.value(QStringLiteral("fingerprint")).toString();
    }
    if (authObject.contains(QStringLiteral("slot_code"))) {
        settings_.auth.slotCode = authObject.value(QStringLiteral("slot_code")).toString();
    }

    const QJsonObject generalObject = object.value(QStringLiteral("general")).toObject();
    if (generalObject.contains(QStringLiteral("last_target_path"))) {
        settings_.general.lastTargetPath = generalObject.value(QStringLiteral("last_target_path")).toString();
    }
}

QJsonObject SettingsManager::toJson() const
{
    QJsonObject authObject;
    authObject.insert(QStringLiteral("base_url"), settings_.auth.baseUrl);
    authObject.insert(QStringLiteral("card_code"), settings_.auth.cardCode);
    authObject.insert(QStringLiteral("license_secret"), settings_.auth.licenseSecret);
    authObject.insert(QStringLiteral("slot_secret"), settings_.auth.slotSecret);
    authObject.insert(QStringLiteral("fingerprint"), settings_.auth.fingerprint);
    authObject.insert(QStringLiteral("slot_code"), settings_.auth.slotCode);

    QJsonObject generalObject;
    generalObject.insert(QStringLiteral("last_target_path"), settings_.general.lastTargetPath);

    QJsonObject root;
    root.insert(QStringLiteral("auth"), authObject);
    root.insert(QStringLiteral("general"), generalObject);
    return root;
}

} // namespace core
