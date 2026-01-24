#pragma once

#include <string>
#include <deque>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace utils {

enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERR
};

class Logger {
public:
    static void Log(LogLevel level, const std::string& msg);
    static std::string GetRecentLogs(size_t maxLines = 100);

private:
    static std::mutex mtx_;
    static std::deque<std::string> ring_;
    static constexpr size_t MAX_LINES = 512;
};

} // namespace utils

#ifdef _DEBUG
#define LOG_DEBUG(msg) utils::Logger::Log(utils::LogLevel::DEBUG, msg)
#else
#define LOG_DEBUG(msg)
#endif

#define LOG_INFO(msg) utils::Logger::Log(utils::LogLevel::INFO, msg)
#define LOG_WARN(msg) utils::Logger::Log(utils::LogLevel::WARN, msg)
#define LOG_ERR(msg) utils::Logger::Log(utils::LogLevel::ERR, msg)
