#pragma once
#include <vector>
#include <string>
namespace evasion {
class Detection {
public:
    static bool IsAVPresent();
    static bool IsEDRPresent();
    static int GetJitterDelay();
private:
#ifdef _WIN32
    static bool IsProcessRunning(const std::wstring& processName);
#else
    static bool IsProcessRunning(const std::string& processName);
#endif
};
}
