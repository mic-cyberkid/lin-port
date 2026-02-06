#include "Logger.h"
#include <windows.h>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <sstream>

namespace utils {

std::mutex Logger::logMutex_;
std::deque<std::string> Logger::logBuffer_;

void Logger::Log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex_);

    const char* levelStr = "INFO";
    switch (level) {
        case LogLevel::DEBUG: levelStr = "DEBUG"; break;
        case LogLevel::INFO:  levelStr = "INFO";  break;
        case LogLevel::WARN:  levelStr = "WARN";  break;
        case LogLevel::ERR:   levelStr = "ERROR"; break;
    }

    std::time_t now = std::time(nullptr);
    char timestamp[32];
    struct tm timeinfo;
    if (localtime_s(&timeinfo, &now) == 0) {
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);
    } else {
        std::strcpy(timestamp, "0000-00-00 00:00:00");
    }

    char formatted[2048];
    std::snprintf(formatted, sizeof(formatted), "[%s] [%s] %s\n", timestamp, levelStr, message.c_str());

    // 1. Log to Debugger (Safe, only visible to attached debuggers or Sysinternals DebugView)
    OutputDebugStringA(formatted);

    // 2. Log to Memory (Circular buffer)
    logBuffer_.push_back(formatted);
    if (logBuffer_.size() > 200) logBuffer_.pop_front();
}

std::string Logger::GetRecentLogs() {
    std::lock_guard<std::mutex> lock(logMutex_);
    std::string all;
    for (const auto& log : logBuffer_) all += log;
    return all;
}

} // namespace utils
