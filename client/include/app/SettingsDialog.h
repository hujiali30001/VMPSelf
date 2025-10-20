#pragma once

#include <QDialog>
#include <QList>
#include <QPair>
#include <memory>

#include "core/util/SettingsManager.h"

class QLineEdit;
class QComboBox;
class QLabel;
class QDialogButtonBox;
class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(const core::AuthSettings &authSettings, QWidget *parent = nullptr);

    [[nodiscard]] core::AuthSettings authSettings() const;

private slots:
    void onFieldChanged();
    void onBaseUrlTextChanged(const QString &text);
    void onSlotSelectionChanged(const QString &text);
    void onSlotFetchFinished();

private:
    void setupUi();
    void updateStateFrom(const core::AuthSettings &authSettings);
    void updateValidationState();
    void scheduleSlotRefresh();
    void fetchSlotList();
    void applySlotOptions(const QList<QPair<QString, QString>> &options);

    QLineEdit *baseUrlEdit_ = nullptr;
    QLineEdit *cardCodeEdit_ = nullptr;
    QLineEdit *licenseSecretEdit_ = nullptr;
    QLineEdit *fingerprintEdit_ = nullptr;
    QComboBox *slotCodeCombo_ = nullptr;
    QLabel *validationLabel_ = nullptr;
    QLabel *slotStatusLabel_ = nullptr;
    QDialogButtonBox *buttonBox_ = nullptr;
    QNetworkAccessManager *networkManager_ = nullptr;
    QTimer *slotRefreshTimer_ = nullptr;
    bool isFetchingSlots_ = false;
};
