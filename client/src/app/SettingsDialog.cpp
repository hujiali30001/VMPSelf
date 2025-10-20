#include "app/SettingsDialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPalette>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStringList>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

#include <algorithm>

namespace {
constexpr auto DIALOG_TITLE = "授权服务器设置";
constexpr auto PLACEHOLDER_BASE_URL = "http://192.168.132.132:11000";
constexpr auto PLACEHOLDER_CARD_CODE = "CARD-TEST";
constexpr auto PLACEHOLDER_SLOT_CODE = "default-slot";
constexpr auto PLACEHOLDER_FINGERPRINT = "fp-12345";
constexpr auto PLACEHOLDER_SLOT_SECRET = "槽位秘钥（可选）";
constexpr auto SLOT_ENDPOINT_PATH = "/api/v1/software/slots";
}

SettingsDialog::SettingsDialog(const core::AuthSettings &authSettings, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr(DIALOG_TITLE));
    setModal(true);
    setupUi();
    updateStateFrom(authSettings);
    updateValidationState();
    scheduleSlotRefresh();
}

core::AuthSettings SettingsDialog::authSettings() const
{
    core::AuthSettings settings;
    settings.baseUrl = baseUrlEdit_->text().trimmed();
    settings.cardCode = cardCodeEdit_->text().trimmed();
    settings.licenseSecret = licenseSecretEdit_->text();
    settings.slotSecret = slotSecretEdit_->text().trimmed();
    settings.fingerprint = fingerprintEdit_->text().trimmed();
    settings.slotCode = slotCodeCombo_->currentText().trimmed();
    return settings;
}

void SettingsDialog::setupUi()
{
    auto *layout = new QVBoxLayout(this);

    auto *formLayout = new QFormLayout();
    baseUrlEdit_ = new QLineEdit(this);
    baseUrlEdit_->setPlaceholderText(tr(PLACEHOLDER_BASE_URL));
    baseUrlEdit_->setClearButtonEnabled(true);
    formLayout->addRow(tr("服务地址"), baseUrlEdit_);

    cardCodeEdit_ = new QLineEdit(this);
    cardCodeEdit_->setPlaceholderText(tr(PLACEHOLDER_CARD_CODE));
    cardCodeEdit_->setClearButtonEnabled(true);
    formLayout->addRow(tr("测试卡号"), cardCodeEdit_);

    licenseSecretEdit_ = new QLineEdit(this);
    licenseSecretEdit_->setEchoMode(QLineEdit::Password);
    licenseSecretEdit_->setClearButtonEnabled(true);
    formLayout->addRow(tr("授权密钥"), licenseSecretEdit_);

    slotSecretEdit_ = new QLineEdit(this);
    slotSecretEdit_->setEchoMode(QLineEdit::Password);
    slotSecretEdit_->setClearButtonEnabled(true);
    slotSecretEdit_->setPlaceholderText(tr(PLACEHOLDER_SLOT_SECRET));
    formLayout->addRow(tr("槽位密钥"), slotSecretEdit_);

    slotCodeCombo_ = new QComboBox(this);
    slotCodeCombo_->setEditable(true);
    slotCodeCombo_->setInsertPolicy(QComboBox::NoInsert);
    slotCodeCombo_->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    slotCodeCombo_->setMinimumContentsLength(1);
    if (auto *slotEdit = slotCodeCombo_->lineEdit()) {
        slotEdit->setPlaceholderText(tr(PLACEHOLDER_SLOT_CODE));
        slotEdit->setClearButtonEnabled(true);
    }
    formLayout->addRow(tr("软件槽标识"), slotCodeCombo_);

    fingerprintEdit_ = new QLineEdit(this);
    fingerprintEdit_->setPlaceholderText(tr(PLACEHOLDER_FINGERPRINT));
    fingerprintEdit_->setClearButtonEnabled(true);
    formLayout->addRow(tr("设备指纹"), fingerprintEdit_);

    layout->addLayout(formLayout);

    slotStatusLabel_ = new QLabel(this);
    slotStatusLabel_->setWordWrap(true);
    slotStatusLabel_->setStyleSheet(QStringLiteral("color: %1").arg(palette().color(QPalette::WindowText).darker(125).name()));
    slotStatusLabel_->setText(tr("填写服务地址后可自动加载可用槽位。"));
    layout->addWidget(slotStatusLabel_);

    validationLabel_ = new QLabel(this);
    validationLabel_->setWordWrap(true);
    validationLabel_->setStyleSheet(QStringLiteral("color: %1").arg(palette().color(QPalette::WindowText).darker(150).name()));
    layout->addWidget(validationLabel_);

    buttonBox_ = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    layout->addWidget(buttonBox_);

    connect(buttonBox_, &QDialogButtonBox::accepted, this, &SettingsDialog::accept);
    connect(buttonBox_, &QDialogButtonBox::rejected, this, &SettingsDialog::reject);

    connect(baseUrlEdit_, &QLineEdit::textChanged, this, &SettingsDialog::onBaseUrlTextChanged);
    connect(cardCodeEdit_, &QLineEdit::textChanged, this, &SettingsDialog::onFieldChanged);
    connect(licenseSecretEdit_, &QLineEdit::textChanged, this, &SettingsDialog::onFieldChanged);
    connect(slotSecretEdit_, &QLineEdit::textChanged, this, &SettingsDialog::onFieldChanged);
    connect(fingerprintEdit_, &QLineEdit::textChanged, this, &SettingsDialog::onFieldChanged);
    connect(slotCodeCombo_, &QComboBox::currentTextChanged, this, &SettingsDialog::onSlotSelectionChanged);
    if (auto *slotEdit = slotCodeCombo_->lineEdit()) {
        connect(slotEdit, &QLineEdit::textChanged, this, &SettingsDialog::onFieldChanged);
    }
}

void SettingsDialog::updateStateFrom(const core::AuthSettings &authSettings)
{
    QSignalBlocker blockBase(baseUrlEdit_);
    QSignalBlocker blockCard(cardCodeEdit_);
    QSignalBlocker blockSecret(licenseSecretEdit_);
    QSignalBlocker blockSlotSecret(slotSecretEdit_);
    QSignalBlocker blockFingerprint(fingerprintEdit_);
    QSignalBlocker blockCombo(slotCodeCombo_);
    QSignalBlocker blockComboEdit(slotCodeCombo_->lineEdit());

    baseUrlEdit_->setText(authSettings.baseUrl);
    cardCodeEdit_->setText(authSettings.cardCode);
    licenseSecretEdit_->setText(authSettings.licenseSecret);
    slotSecretEdit_->setText(authSettings.slotSecret);
    slotCodeCombo_->setEditText(authSettings.slotCode);
    fingerprintEdit_->setText(authSettings.fingerprint);
}

void SettingsDialog::onFieldChanged()
{
    updateValidationState();
}

void SettingsDialog::onBaseUrlTextChanged(const QString &)
{
    onFieldChanged();
    scheduleSlotRefresh();
}

void SettingsDialog::onSlotSelectionChanged(const QString &)
{
    updateValidationState();
}

void SettingsDialog::onSlotFetchFinished()
{
    auto *reply = qobject_cast<QNetworkReply *>(sender());
    if (!reply) {
        return;
    }

    reply->deleteLater();
    isFetchingSlots_ = false;

    if (reply->error() != QNetworkReply::NoError) {
        slotStatusLabel_->setText(tr("获取槽位失败：%1").arg(reply->errorString()));
        return;
    }

    const QByteArray payload = reply->readAll();
    QJsonParseError parseError{};
    const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        slotStatusLabel_->setText(tr("槽位响应格式无效：%1").arg(parseError.errorString()));
        return;
    }
    if (!document.isArray()) {
        slotStatusLabel_->setText(tr("槽位响应格式无效"));
        return;
    }

    QList<QPair<QString, QString>> options;
    const auto array = document.array();
    options.reserve(array.size());
    for (const auto &value : array) {
        if (!value.isObject()) {
            continue;
        }
        const auto object = value.toObject();
        const QString code = object.value(QStringLiteral("code")).toString().trimmed();
        if (code.isEmpty()) {
            continue;
        }
        const QString name = object.value(QStringLiteral("name")).toString().trimmed();
        options.append({code, name});
    }

    std::sort(options.begin(), options.end(), [](const auto &lhs, const auto &rhs) {
        return lhs.first.toLower() < rhs.first.toLower();
    });

    if (options.isEmpty()) {
        slotStatusLabel_->setText(tr("服务器未返回可用槽位。"));
    } else {
        slotStatusLabel_->setText(tr("已加载 %1 个槽位。请选择或直接输入。").arg(options.size()));
    }

    applySlotOptions(options);
    updateValidationState();
}

void SettingsDialog::updateValidationState()
{
    QStringList warnings;
    const QString baseUrl = baseUrlEdit_->text().trimmed();
    const QString cardCode = cardCodeEdit_->text().trimmed();
    const QString secret = licenseSecretEdit_->text();
    const QString slotSecret = slotSecretEdit_->text().trimmed();
    const QString slotCode = slotCodeCombo_->currentText().trimmed();
    const QString fingerprint = fingerprintEdit_->text().trimmed();

    bool valid = true;

    if (baseUrl.isEmpty()) {
        warnings << tr("服务地址不能为空");
        valid = false;
    } else {
        const QUrl url = QUrl::fromUserInput(baseUrl);
        if (!url.isValid() || url.scheme().isEmpty() || (!url.scheme().startsWith(QStringLiteral("http")))) {
            warnings << tr("服务地址无效，请输入 http(s) URL");
            valid = false;
        }
    }

    if (cardCode.isEmpty()) {
        warnings << tr("请提供测试卡号");
        valid = false;
    }

    if (secret.isEmpty() && slotSecret.isEmpty()) {
        warnings << tr("请至少填写授权密钥或槽位密钥");
        valid = false;
    }

    if (slotCode.isEmpty()) {
        warnings << tr("请填写软件槽标识");
        valid = false;
    }

    if (fingerprint.isEmpty()) {
        warnings << tr("请填写设备指纹");
        valid = false;
    }

    if (warnings.isEmpty()) {
        validationLabel_->setText(tr("参数将用于授权激活测试与离线许可请求。"));
    } else {
        validationLabel_->setText(warnings.join(QStringLiteral("\n")));
    }

    if (auto *okButton = buttonBox_->button(QDialogButtonBox::Ok)) {
        okButton->setEnabled(valid);
    }
}

void SettingsDialog::scheduleSlotRefresh()
{
    if (!slotRefreshTimer_) {
        slotRefreshTimer_ = new QTimer(this);
        slotRefreshTimer_->setSingleShot(true);
        connect(slotRefreshTimer_, &QTimer::timeout, this, &SettingsDialog::fetchSlotList);
    }
    slotRefreshTimer_->start(400);
}

void SettingsDialog::fetchSlotList()
{
    if (isFetchingSlots_) {
        if (slotRefreshTimer_) {
            slotRefreshTimer_->start(400);
        }
        return;
    }

    const QString baseUrl = baseUrlEdit_->text().trimmed();
    if (baseUrl.isEmpty()) {
        slotStatusLabel_->setText(tr("请输入服务地址以获取服务器槽位列表。"));
        return;
    }

    const QUrl url = QUrl::fromUserInput(baseUrl);
    if (!url.isValid() || url.scheme().isEmpty() || (!url.scheme().startsWith(QStringLiteral("http")))) {
        slotStatusLabel_->setText(tr("服务地址无效，无法获取槽位列表。"));
        return;
    }

    QUrl requestUrl(url);
    requestUrl.setPath(QString::fromUtf8(SLOT_ENDPOINT_PATH));
    requestUrl.setQuery(QString());

    if (!networkManager_) {
        networkManager_ = new QNetworkAccessManager(this);
    }

    slotStatusLabel_->setText(tr("正在从服务器获取槽位列表…"));
    isFetchingSlots_ = true;
    auto *reply = networkManager_->get(QNetworkRequest(requestUrl));
    connect(reply, &QNetworkReply::finished, this, &SettingsDialog::onSlotFetchFinished);
}

void SettingsDialog::applySlotOptions(const QList<QPair<QString, QString>> &options)
{
    const QString previousSelection = slotCodeCombo_->currentText().trimmed();

    slotCodeCombo_->blockSignals(true);
    QLineEdit *slotEdit = slotCodeCombo_->lineEdit();
    if (slotEdit) {
        slotEdit->blockSignals(true);
    }

    slotCodeCombo_->clear();
    for (const auto &option : options) {
        const QString &code = option.first;
        const QString &name = option.second;
        const QString label = name.isEmpty() ? code : tr("%1 (%2)").arg(code, name);
        slotCodeCombo_->addItem(label, code);
    }

    if (!previousSelection.isEmpty()) {
        const int index = slotCodeCombo_->findData(previousSelection);
        if (index >= 0) {
            slotCodeCombo_->setCurrentIndex(index);
        } else {
            slotCodeCombo_->setEditText(previousSelection);
        }
    } else if (!options.isEmpty()) {
        slotCodeCombo_->setCurrentIndex(0);
    } else if (slotEdit) {
        slotEdit->clear();
    }

    slotCodeCombo_->blockSignals(false);
    if (slotEdit) {
        slotEdit->blockSignals(false);
    }
}
