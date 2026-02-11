#include "Logger.h"
#include "Obfuscator.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#endif
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
#ifdef _WIN32
    if (localtime_s(&timeinfo, &now) == 0) {
#else
    if (localtime_r(&now, &timeinfo) != nullptr) {
#endif
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);
    } else {
        std::strcpy(timestamp, "0000-00-00 00:00:00");
    }

    char formatted[2048];
    std::snprintf(formatted, sizeof(formatted), "[%s] [%s] %s\n", timestamp, levelStr, message.c_str());

#ifdef _WIN32
    OutputDebugStringA(formatted);
#else
    std::fprintf(stderr, "%s", formatted);
#endif

    logBuffer_.push_back(formatted);
    if (logBuffer_.size() > 200) logBuffer_.pop_front();

#ifdef _WIN32
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        std::string logPath = std::string(tempPath) + "win_update_cache.tmp";
        FILE* f = std::fopen(logPath.c_str(), "a");
        if (f) {
            std::fprintf(f, "%s", formatted);
            std::fclose(f);
        }
    }
#else
    const char* tmp = std::getenv("TMPDIR");
    if (!tmp) tmp = "/tmp";
    std::string logPath = std::string(tmp) + "/.system_cache.tmp";
    FILE* f = std::fopen(logPath.c_str(), "a");
    if (f) {
        std::fprintf(f, "%s", formatted);
        std::fclose(f);
    }
#endif
}

std::string Logger::GetRecentLogs() {
    std::lock_guard<std::mutex> lock(logMutex_);
    std::string all;
    for (const auto& log : logBuffer_) all += log;
    return all;
}

} // namespace utils
