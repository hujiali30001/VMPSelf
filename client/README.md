# Qt 客户端壳工具

## 环境
- Windows 10/11
- Qt 5.12.12 (msvc2017_64 与 msvc2017 32-bit 套件)
- Visual Studio 2019 + MSVC v141 工具集
- CMake 3.16+

## 构建
```powershell
mkdir build
cd build
cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH="C:/Qt/Qt5.12.12/5.12.12/msvc2017_64" ..
cmake --build .
```

## 目录说明
- `include/app`：UI 壳框架。
- `include/core`：PE 解析、虚拟机、授权、驱动通信等模块接口。
- `src/app`：Qt 主窗口及信号槽实现。
- `src/core`：核心模块的占位实现，后续可扩展真实逻辑。

## 授权客户端使用示例
```cpp
#include <core/auth/AuthClient.h>

core::AuthClient client;
core::AuthClientConfig config;
config.baseUrl = QUrl("https://auth.example.com");
config.cardCode = "CARD-0001";
config.licenseSecret = "base64-or-random-secret";
config.fingerprint = "machine-fingerprint";

client.setConfig(config);
if (client.testConnection()) {
	auto session = client.activate();
	if (session) {
		// 根据 session->heartbeatIntervalSeconds 定时调用 sendHeartbeat()
		auto offline = client.requestOfflineLicense(QDateTime::currentDateTimeUtc().addDays(3));
		if (offline) {
			QFile file("offline_license.json");
			if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
				file.write(offline->serializedPayload);
			}
		}
	}
}
```

- `AuthClient::activate()` 会自动计算 `card_code|fingerprint|timestamp` 的 HMAC-SHA256（Base64），并解析返回的 token 与过期时间。
- 调用 `AuthClient::sendHeartbeat()` 会重用现有 token 发送心跳，失败时可通过 `lastError()` 获取原因。
- `AuthClient::requestOfflineLicense()` 会向服务器索取离线授权文件并立即校验签名，可通过 `offlineLicense()->signature` 保存原始签名；离线启动时调用 `loadOfflineLicense()` 校验本地文件，同时 `hasValidOfflineLicense()` 可快速判断是否仍在有效期内。

## 下一步
- 实现 `PEParser` 读取 PE 头、节表。
- 编写虚拟机字节码设计与解释器。
- 集成 `AuthClient` 与服务端签名协议。
- 扩展 `ProtectionPassManager` 以支持多阶段保护。
