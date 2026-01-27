#include "Logger.h"
#include <windows.h>
#include <cstdio>
#include <ctime>

namespace utils {

std::mutex Logger::logMutex_;

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
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    std::printf("[%s] [%s] %s\n", timestamp, levelStr, message.c_str());
    
    // Also send to debugger if attached
    std::string dbgMsg = "[" + std::string(levelStr) + "] " + message + "\n";
    OutputDebugStringA(dbgMsg.c_str());
}

} // namespace utils
