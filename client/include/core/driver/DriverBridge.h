#pragma once

#include <QString>

namespace core {

class DriverBridge
{
public:
    bool loadDriver(const QString &path);
    bool unloadDriver();
    bool sendPing();
};

} // namespace core
