#include "Logger.h"
#include <windows.h>
#include <cstdio>
#include <ctime>
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
    char timestamp[20];
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);

    char formatted[1024];
    std::snprintf(formatted, sizeof(formatted), "[%s] [%s] %s", timestamp, levelStr, message.c_str());
    std::string logLine(formatted);

    std::printf("%s\n", logLine.c_str());
    
    // Add to circular buffer
    logBuffer_.push_back(logLine);
    if (logBuffer_.size() > MAX_LOG_SIZE) {
        logBuffer_.pop_front();
    }

    // Also send to debugger if attached
    std::string dbgMsg = logLine + "\n";
    OutputDebugStringA(dbgMsg.c_str());
}

std::string Logger::GetRecentLogs() {
    std::lock_guard<std::mutex> lock(logMutex_);
    std::stringstream ss;
    for (const auto& log : logBuffer_) {
        ss << log << "\n";
    }
    // Optional: clear buffer after retrieval?
    // Usually better to keep it or mark it. Let's keep it but maybe limited.
    // Memory says "retrieves and clears" is often intended for these tasks.
    logBuffer_.clear();
    return ss.str();
}

} // namespace utils
