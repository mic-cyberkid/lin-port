#include "Logger.h"
#include "Shared.h"
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

    char formatted[1024];
    std::snprintf(formatted, sizeof(formatted), "[%s] [%s] %s\r\n", timestamp, levelStr, message.c_str());
    std::string logLine(formatted);

    // 1. Log to circular buffer
    logBuffer_.push_back(logLine);
    if (logBuffer_.size() > MAX_LOG_SIZE) {
        logBuffer_.pop_front();
    }

    // 2. Log to Debugger
    OutputDebugStringA(formatted);

    // 3. Log to File via direct Win32 API for maximum reliability
    // Path: C:\Users\Public\debug_implant.log
    std::wstring logPath = L"C:\\Users\\Public\\debug_implant.log";
    HANDLE hFile = CreateFileW(logPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, logLine.c_str(), (DWORD)logLine.length(), &written, NULL);
        CloseHandle(hFile);
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
