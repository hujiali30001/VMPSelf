#pragma once

#include <QJsonObject>
#include <QString>
#include <optional>

#include "core/auth/AuthClient.h"

namespace core {

struct AuthSettings
{
    QString baseUrl;
    QString cardCode;
    QString licenseSecret;
    QString slotSecret;
    QString fingerprint;
    QString slotCode;
};

struct GeneralSettings
{
    QString lastTargetPath;
};

struct Settings
{
    AuthSettings auth;
    GeneralSettings general;
};

class SettingsManager
{
public:
    SettingsManager();
    explicit SettingsManager(QString configFilePath);

    bool load();
    bool save() const;

    Settings &settings();
    const Settings &settings() const;

    void setAuthSettings(const AuthSettings &authSettings);
    [[nodiscard]] AuthSettings authSettings() const;

    void setLastTargetPath(const QString &path);
    [[nodiscard]] QString lastTargetPath() const;

    [[nodiscard]] std::optional<AuthClientConfig> authClientConfig() const;

    [[nodiscard]] QString configFilePath() const;
    void setConfigFilePath(const QString &path);

    static QString defaultConfigFilePath();

private:
    QString configFilePath_;
    Settings settings_;

    void fromJson(const QJsonObject &object);
    [[nodiscard]] QJsonObject toJson() const;
};

} // namespace core
