#include "core/util/Logger.h"

#include <QDateTime>
#include <QDebug>

namespace core {

Logger &Logger::instance()
{
    static Logger logger;
    return logger;
}

void Logger::setSink(Sink sink)
{
    std::lock_guard<std::mutex> lock(mutex_);
    sink_ = std::move(sink);
}

void Logger::log(const QString &message)
{
    const QString formatted = QString("[%1] %2")
                                   .arg(QDateTime::currentDateTime().toString(Qt::ISODate))
                                   .arg(message);

    Sink currentSink;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        currentSink = sink_;
    }

    if (currentSink) {
        currentSink(formatted);
    } else {
        qInfo().noquote() << formatted;
    }
}

} // namespace core
