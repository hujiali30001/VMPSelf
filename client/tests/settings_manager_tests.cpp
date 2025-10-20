#include <gtest/gtest.h>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include "core/util/SettingsManager.h"

namespace {

TEST(SettingsManagerTests, SavesAndLoadsConfiguration)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString configPath = tempDir.filePath(QStringLiteral("settings.json"));

    core::SettingsManager manager(configPath);
    core::AuthSettings authSettings;
    authSettings.baseUrl = QStringLiteral("https://auth.example.com");
    authSettings.cardCode = QStringLiteral("CARD-TEST");
    authSettings.licenseSecret = QStringLiteral("super-secret");
    authSettings.fingerprint = QStringLiteral("FINGERPRINT");
    authSettings.slotCode = QStringLiteral("default-slot");

    manager.setAuthSettings(authSettings);
    manager.setLastTargetPath(QStringLiteral("C:/Samples"));

    EXPECT_TRUE(manager.save());

    core::SettingsManager reloaded(configPath);
    EXPECT_TRUE(reloaded.load());

    const core::AuthSettings loadedAuth = reloaded.authSettings();
    EXPECT_EQ(loadedAuth.baseUrl, authSettings.baseUrl);
    EXPECT_EQ(loadedAuth.cardCode, authSettings.cardCode);
    EXPECT_EQ(loadedAuth.licenseSecret, authSettings.licenseSecret);
    EXPECT_EQ(loadedAuth.fingerprint, authSettings.fingerprint);
    EXPECT_EQ(reloaded.lastTargetPath(), QStringLiteral("C:/Samples"));

    const auto authConfig = reloaded.authClientConfig();
    ASSERT_TRUE(authConfig.has_value());
    EXPECT_EQ(authConfig->cardCode, authSettings.cardCode);
    EXPECT_EQ(authConfig->licenseSecret, authSettings.licenseSecret);
    EXPECT_EQ(authConfig->fingerprint, authSettings.fingerprint);
    EXPECT_EQ(authConfig->baseUrl.toString(), authSettings.baseUrl);
    EXPECT_EQ(authConfig->slotCode, authSettings.slotCode);
}

TEST(SettingsManagerTests, ReturnsNulloptForIncompleteConfig)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString configPath = tempDir.filePath(QStringLiteral("settings.json"));

    core::SettingsManager manager(configPath);
    core::AuthSettings authSettings;
    authSettings.baseUrl = QStringLiteral("not a url");
    authSettings.cardCode = QStringLiteral("CARD-TEST");
    authSettings.licenseSecret = QStringLiteral("secret");
    authSettings.fingerprint = QStringLiteral("fingerprint");
    authSettings.slotCode = QStringLiteral("demo-slot");

    manager.setAuthSettings(authSettings);

    EXPECT_FALSE(manager.authClientConfig().has_value());

    authSettings.baseUrl = QStringLiteral("https://auth.example.com");
    authSettings.cardCode.clear();
    manager.setAuthSettings(authSettings);

    EXPECT_FALSE(manager.authClientConfig().has_value());

    authSettings.cardCode = QStringLiteral("CARD-TEST");
    authSettings.slotCode.clear();
    manager.setAuthSettings(authSettings);

    EXPECT_FALSE(manager.authClientConfig().has_value());
}

} // namespace
