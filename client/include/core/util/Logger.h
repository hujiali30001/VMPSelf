#pragma once

#include <QString>
#include <functional>
#include <mutex>

namespace core {

class Logger
{
public:
    using Sink = std::function<void(const QString&)>;

    static Logger& instance();

    void setSink(Sink sink);
    void log(const QString& message);

private:
    Logger() = default;
    std::mutex mutex_;
    Sink sink_;
};

} // namespace core
