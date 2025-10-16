#include "core/driver/DriverBridge.h"

#include "core/util/Logger.h"

namespace core {

bool DriverBridge::loadDriver(const QString &path)
{
    Logger::instance().log(QString("DriverBridge: 加载驱动 (占位) -> %1").arg(path));
    return true;
}

bool DriverBridge::unloadDriver()
{
    Logger::instance().log("DriverBridge: 卸载驱动 (占位)");
    return true;
}

bool DriverBridge::sendPing()
{
    Logger::instance().log("DriverBridge: Ping 驱动 (占位)");
    return true;
}

} // namespace core
