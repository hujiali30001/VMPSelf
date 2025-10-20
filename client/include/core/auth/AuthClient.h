#pragma once

#include <QObject>
#include <QByteArray>
#include <QDateTime>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QUrl>
#include <optional>

namespace core {

struct AuthClientConfig
{
    QUrl baseUrl;
    QString cardCode;
    QString licenseSecret;
    QString slotSecret;
    QString fingerprint;
    QString slotCode;
};

struct AuthSession
{
    QString token;
    QDateTime expiresAtUtc;
    int heartbeatIntervalSeconds = 0;
};

struct OfflineLicense
{
    QString cardCode;
    QString fingerprint;
    QString token;
    QDateTime expiresAtUtc;
    QDateTime issuedAtUtc;
    QByteArray serializedPayload;
    QString signature;
};

class AuthClient : public QObject
{
    Q_OBJECT

public:
    explicit AuthClient(QObject *parent = nullptr);

    void setConfig(AuthClientConfig config);
    [[nodiscard]] const std::optional<AuthClientConfig>& config() const;

    bool testConnection();
    std::optional<AuthSession> activate();
    bool sendHeartbeat();
    [[nodiscard]] const std::optional<AuthSession>& session() const;
    [[nodiscard]] QString lastError() const;
    std::optional<OfflineLicense> requestOfflineLicense(const QDateTime &expiresAtUtc);
    bool loadOfflineLicense(const QByteArray &licenseBlob, const QString &signature);
    [[nodiscard]] const std::optional<OfflineLicense>& offlineLicense() const;
    [[nodiscard]] bool hasValidOfflineLicense() const;

signals:
    void logMessage(const QString &message);

private:
    std::optional<AuthClientConfig> config_;
    std::optional<AuthSession> session_;
    std::optional<OfflineLicense> offlineLicense_;
    QString lastError_;
    QNetworkAccessManager network_;

    void setLastError(QString message);
    bool ensureConfig() const;
    QByteArray buildSignature(const QString &cardCode, const QString &fingerprint, qint64 timestamp, const QString &secret) const;
    std::optional<QByteArray> postJson(const QString &path, const QJsonObject &payload);
    bool verifyOfflineSignature(const QByteArray &licenseBlob, const QString &signature) const;
};

} // namespace core
