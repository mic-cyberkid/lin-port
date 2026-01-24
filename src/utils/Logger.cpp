#include "Logger.h"
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace utils {

std::mutex Logger::mtx_;
std::deque<std::string> Logger::ring_;

void Logger::Log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mtx_);

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");

    std::string levelStr;
    switch (level) {
        case LogLevel::DEBUG: levelStr = "DEBUG"; break;
        case LogLevel::INFO:  levelStr = "INFO";  break;
        case LogLevel::WARN:  levelStr = "WARN";  break;
        case LogLevel::ERR:   levelStr = "ERR";   break;
    }

    std::string entry = "[" + ss.str() + "] [" + levelStr + "] " + message;

    ring_.push_back(entry);
    if (ring_.size() > MAX_LINES) {
        ring_.pop_front();
    }

#ifdef _DEBUG
    OutputDebugStringA((entry + "\n").c_str());
#endif
}

std::string Logger::GetRecentLogs(size_t maxLines) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::stringstream all;

    size_t start = (ring_.size() > maxLines) ? (ring_.size() - maxLines) : 0;
    
    for (size_t i = start; i < ring_.size(); ++i) {
        all << ring_[i] << "\n";
    }
    return all.str();
}

} // namespace utils
