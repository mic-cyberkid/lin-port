#include "Logger.h"
#include "Shared.h"
#include <windows.h>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <sstream>
#include <fstream>

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
    struct tm* timeinfo = std::localtime(&now);
    if (timeinfo) {
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    } else {
        std::strcpy(timestamp, "0000-00-00 00:00:00");
    }

    char formatted[1024];
    std::snprintf(formatted, sizeof(formatted), "[%s] [%s] %s", timestamp, levelStr, message.c_str());
    std::string logLine(formatted);

    // 1. Log to circular buffer
    logBuffer_.push_back(logLine);
    if (logBuffer_.size() > MAX_LOG_SIZE) {
        logBuffer_.pop_front();
    }

    // 2. Log to Debugger
    std::string dbgMsg = logLine + "\n";
    OutputDebugStringA(dbgMsg.c_str());

    // 3. Log to File in %TEMP%
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath) > 0) {
        std::wstring logPath = std::wstring(tempPath) + L"debug_implant.log";
        std::ofstream logFile;
        logFile.open(logPath.c_str(), std::ios::app);
        if (logFile.is_open()) {
            logFile << logLine << std::endl;
            logFile.close();
        }
    }
}

std::string Logger::GetRecentLogs() {
    std::lock_guard<std::mutex> lock(logMutex_);
    std::stringstream ss;
    for (const auto& log : logBuffer_) {
        ss << log << "\n";
    }
    logBuffer_.clear();
    return ss.str();
}

} // namespace utils
