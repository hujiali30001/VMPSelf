#pragma execution_character_set("utf-8")

#include "core/auth/AuthClient.h"

#include <QDateTime>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QMessageAuthenticationCode>
#include <QCryptographicHash>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QVariant>
#include <memory>

#include "core/util/Logger.h"

namespace core {

namespace {

QString isoDateString(const QDateTime &dt)
{
    return dt.toUTC().toString(Qt::ISODate);
}

} // namespace

AuthClient::AuthClient(QObject *parent)
    : QObject(parent)
{
    connect(this, &AuthClient::logMessage, [](const QString &msg) {
        Logger::instance().log(msg);
    });
}

void AuthClient::setConfig(AuthClientConfig config)
{
    config_ = std::move(config);
    session_.reset();
    offlineLicense_.reset();
    lastError_.clear();
}

const std::optional<AuthClientConfig> &AuthClient::config() const
{
    return config_;
}

const std::optional<AuthSession> &AuthClient::session() const
{
    return session_;
}

QString AuthClient::lastError() const
{
    return lastError_;
}

void AuthClient::setLastError(QString message)
{
    lastError_ = std::move(message);
    if (!lastError_.isEmpty()) {
        emit logMessage(QStringLiteral("AuthClient: %1").arg(lastError_));
    }
}

bool AuthClient::ensureConfig() const
{
    if (!config_) {
        const_cast<AuthClient *>(this)->setLastError(QStringLiteral("未配置服务器参数"));
        return false;
    }
    if (config_->baseUrl.isEmpty() || config_->cardCode.isEmpty() || config_->licenseSecret.isEmpty()) {
        const_cast<AuthClient *>(this)->setLastError(QStringLiteral("配置缺少 baseUrl/cardCode/licenseSecret"));
        return false;
    }
    if (config_->fingerprint.isEmpty()) {
        const_cast<AuthClient *>(this)->setLastError(QStringLiteral("未设置设备指纹"));
        return false;
    }
    if (config_->slotCode.isEmpty()) {
        const_cast<AuthClient *>(this)->setLastError(QStringLiteral("未设置软件槽标识"));
        return false;
    }
    return true;
}

QByteArray AuthClient::buildSignature(
    const QString &cardCode,
    const QString &fingerprint,
    qint64 timestamp,
    const QString &secret) const
{
    const QString message = QStringLiteral("%1|%2|%3")
                                .arg(cardCode, fingerprint, QString::number(timestamp));
    const QByteArray hash = QMessageAuthenticationCode::hash(
        message.toUtf8(),
        secret.toUtf8(),
        QCryptographicHash::Sha256);
    return hash.toBase64();
}

std::optional<QByteArray> AuthClient::postJson(const QString &path, const QJsonObject &payload)
{
    if (!ensureConfig()) {
        return std::nullopt;
    }

    QUrl url = config_->baseUrl;
    url.setPath(path);

    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    QEventLoop loop;
    auto *reply = network_.post(request, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    const auto guard = std::unique_ptr<QNetworkReply, void (*)(QNetworkReply *)>(reply, [](QNetworkReply *r) {
        r->deleteLater();
    });

    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (reply->error() != QNetworkReply::NoError || status >= 400) {
        setLastError(QStringLiteral("请求失败 (%1): %2").arg(status).arg(reply->errorString()));
        return std::nullopt;
    }

    lastError_.clear();
    return reply->readAll();
}

bool AuthClient::testConnection()
{
    if (!config_) {
        setLastError(QStringLiteral("未配置服务器参数"));
        return false;
    }

    QUrl url = config_->baseUrl;
    url.setPath(QStringLiteral("/api/v1/ping"));

    QNetworkRequest request(url);

    QEventLoop loop;
    auto *reply = network_.get(request);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    const auto guard = std::unique_ptr<QNetworkReply, void (*)(QNetworkReply *)>(reply, [](QNetworkReply *r) {
        r->deleteLater();
    });

    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (reply->error() != QNetworkReply::NoError || status >= 400) {
        setLastError(QStringLiteral("请求失败 (%1): %2").arg(status).arg(reply->errorString()));
        return false;
    }

    const auto data = reply->readAll();
    const QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) {
        setLastError(QStringLiteral("服务器返回无效数据"));
        return false;
    }

    const auto obj = doc.object();
    if (obj.value(QStringLiteral("message")).toString() != QStringLiteral("pong")) {
        setLastError(QStringLiteral("服务器返回异常响应"));
        return false;
    }

    emit logMessage(QStringLiteral("AuthClient: 连接服务器成功 (%1)").arg(isoDateString(QDateTime::currentDateTimeUtc())));
    lastError_.clear();
    return true;
}

std::optional<AuthSession> AuthClient::activate()
{
    if (!ensureConfig()) {
        return std::nullopt;
    }

    const qint64 timestamp = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
    const QByteArray signature = buildSignature(
        config_->cardCode,
        config_->fingerprint,
        timestamp,
        config_->licenseSecret);

    QJsonObject payload{
        {QStringLiteral("card_code"), config_->cardCode},
        {QStringLiteral("fingerprint"), config_->fingerprint},
        {QStringLiteral("timestamp"), timestamp},
        {QStringLiteral("signature"), QString::fromUtf8(signature)},
        {QStringLiteral("slot_code"), config_->slotCode},
    };

    auto raw = postJson(QStringLiteral("/api/v1/license/activate"), payload);
    if (!raw) {
        return std::nullopt;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(*raw);
    if (!doc.isObject()) {
        setLastError(QStringLiteral("激活返回数据无效"));
        return std::nullopt;
    }

    const QJsonObject obj = doc.object();
    const QString token = obj.value(QStringLiteral("token")).toString();
    const QString expires = obj.value(QStringLiteral("expires_at")).toString();
    const int hbInterval = obj.value(QStringLiteral("heartbeat_interval_seconds")).toInt();

    const QDateTime expiresUtc = QDateTime::fromString(expires, Qt::ISODate);
    if (token.isEmpty() || !expiresUtc.isValid()) {
        setLastError(QStringLiteral("激活返回 token 或过期时间无效"));
        return std::nullopt;
    }

    AuthSession newSession{
        token,
        expiresUtc.toUTC(),
        hbInterval > 0 ? hbInterval : 300,
    };

    session_ = newSession;
    lastError_.clear();
    emit logMessage(QStringLiteral("AuthClient: 激活成功，token 有效期至 %1")
                        .arg(isoDateString(newSession.expiresAtUtc)));
    return session_;
}

bool AuthClient::sendHeartbeat()
{
    if (!ensureConfig()) {
        return false;
    }
    if (!session_) {
        setLastError(QStringLiteral("尚未激活，无法发送心跳"));
        return false;
    }

    const qint64 timestamp = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
    const QByteArray signature = buildSignature(
        config_->cardCode,
        config_->fingerprint,
        timestamp,
        config_->licenseSecret);

    QJsonObject payload{
        {QStringLiteral("token"), session_->token},
        {QStringLiteral("fingerprint"), config_->fingerprint},
        {QStringLiteral("timestamp"), timestamp},
        {QStringLiteral("signature"), QString::fromUtf8(signature)},
    };

    auto raw = postJson(QStringLiteral("/api/v1/license/heartbeat"), payload);
    if (!raw) {
        return false;
    }

    emit logMessage(QStringLiteral("AuthClient: 心跳已发送 (%1)")
                        .arg(isoDateString(QDateTime::currentDateTimeUtc())));
    return true;
}

std::optional<OfflineLicense> AuthClient::requestOfflineLicense(const QDateTime &expiresAtUtc)
{
    if (!ensureConfig()) {
        return std::nullopt;
    }

    if (!expiresAtUtc.isValid() || expiresAtUtc <= QDateTime::currentDateTimeUtc()) {
        setLastError(QStringLiteral("离线许可过期时间无效"));
        return std::nullopt;
    }

    const qint64 timestamp = expiresAtUtc.toUTC().toSecsSinceEpoch();
    const QByteArray signature = buildSignature(
        config_->cardCode,
        config_->fingerprint,
        timestamp,
        config_->licenseSecret);

    QJsonObject payload{
        {QStringLiteral("card_code"), config_->cardCode},
        {QStringLiteral("fingerprint"), config_->fingerprint},
        {QStringLiteral("expires_at"), expiresAtUtc.toUTC().toString(Qt::ISODate)},
        {QStringLiteral("signature"), QString::fromUtf8(signature)},
    };

    auto raw = postJson(QStringLiteral("/api/v1/license/offline"), payload);
    if (!raw) {
        return std::nullopt;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(*raw);
    if (!doc.isObject()) {
        setLastError(QStringLiteral("离线许可响应无效"));
        return std::nullopt;
    }

    const QJsonObject obj = doc.object();
    const QString licenseBlobStr = obj.value(QStringLiteral("license_blob")).toString();
    const QString signatureStr = obj.value(QStringLiteral("signature")).toString();
    if (licenseBlobStr.isEmpty() || signatureStr.isEmpty()) {
        setLastError(QStringLiteral("离线许可响应缺少字段"));
        return std::nullopt;
    }

    if (!loadOfflineLicense(licenseBlobStr.toUtf8(), signatureStr)) {
        return std::nullopt;
    }

    emit logMessage(QStringLiteral("AuthClient: 获取离线许可成功，有效期至 %1")
                        .arg(isoDateString(offlineLicense_->expiresAtUtc)));
    return offlineLicense_;
}

bool AuthClient::loadOfflineLicense(const QByteArray &licenseBlob, const QString &signature)
{
    if (!ensureConfig()) {
        return false;
    }

    if (!verifyOfflineSignature(licenseBlob, signature)) {
        setLastError(QStringLiteral("离线许可签名校验失败"));
        return false;
    }

    QJsonParseError error;
    const QJsonDocument doc = QJsonDocument::fromJson(licenseBlob, &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) {
        setLastError(QStringLiteral("离线许可解析失败: %1").arg(error.errorString()));
        return false;
    }

    const QJsonObject obj = doc.object();
    const QString cardCode = obj.value(QStringLiteral("card_code")).toString();
    const QString fingerprint = obj.value(QStringLiteral("fingerprint")).toString();
    const QString token = obj.value(QStringLiteral("token")).toString();
    const QString expiresAt = obj.value(QStringLiteral("expires_at")).toString();
    const QString issuedAt = obj.value(QStringLiteral("issued_at")).toString();

    if (cardCode != config_->cardCode || fingerprint != config_->fingerprint) {
        setLastError(QStringLiteral("离线许可卡密或指纹不匹配"));
        return false;
    }

    const QDateTime expiresUtc = QDateTime::fromString(expiresAt, Qt::ISODate).toUTC();
    const QDateTime issuedUtc = QDateTime::fromString(issuedAt, Qt::ISODate).toUTC();
    if (!expiresUtc.isValid() || !issuedUtc.isValid()) {
        setLastError(QStringLiteral("离线许可时间格式无效"));
        return false;
    }

    OfflineLicense offline{
        cardCode,
        fingerprint,
        token,
        expiresUtc,
        issuedUtc,
        licenseBlob,
        signature,
    };

    offlineLicense_ = offline;
    session_ = AuthSession{token, expiresUtc, 0};
    lastError_.clear();
    return true;
}

const std::optional<OfflineLicense> &AuthClient::offlineLicense() const
{
    return offlineLicense_;
}

bool AuthClient::hasValidOfflineLicense() const
{
    if (!offlineLicense_) {
        return false;
    }
    return offlineLicense_->expiresAtUtc > QDateTime::currentDateTimeUtc();
}

bool AuthClient::verifyOfflineSignature(const QByteArray &licenseBlob, const QString &signature) const
{
    if (!config_) {
        return false;
    }
    const QByteArray expected = QMessageAuthenticationCode::hash(
        licenseBlob,
        config_->licenseSecret.toUtf8(),
        QCryptographicHash::Sha256);
    const QByteArray provided = QByteArray::fromBase64(signature.toUtf8());
    if (provided.isEmpty() && !signature.isEmpty()) {
        return false;
    }
    return expected == provided;
}

} // namespace core
