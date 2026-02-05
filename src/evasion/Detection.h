#pragma once
#include <vector>
#include <string>

namespace evasion {

class Detection {
public:
    static bool IsAVPresent();
    static bool IsEDRPresent();
    static int GetJitterDelay(); // Returns suggested extra delay in seconds

private:
    static bool IsProcessRunning(const std::wstring& processName);
};

} // namespace evasion
