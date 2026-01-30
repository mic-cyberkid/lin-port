#pragma once
#include <string>
#include <iostream>
#include <mutex>
#include <deque>
#include <vector>

namespace utils {

enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERR
};

class Logger {
public:
    static void Log(LogLevel level, const std::string& message);
    static void Debug(const std::string& message) { Log(LogLevel::DEBUG, message); }
    static void Info(const std::string& message) { Log(LogLevel::INFO, message); }
    static void Warn(const std::string& message) { Log(LogLevel::WARN, message); }
    static void Error(const std::string& message) { Log(LogLevel::ERR, message); }

    static std::string GetRecentLogs();

private:
    static std::mutex logMutex_;
    static std::deque<std::string> logBuffer_;
    static const size_t MAX_LOG_SIZE = 500;
};

} // namespace utils

#define LOG_DEBUG(msg) utils::Logger::Debug(msg)
#define LOG_INFO(msg)  utils::Logger::Info(msg)
#define LOG_WARN(msg)  utils::Logger::Warn(msg)
#define LOG_ERR(msg)   utils::Logger::Error(msg)
