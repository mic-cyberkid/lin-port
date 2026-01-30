#include "SelfDelete.h"
#include <windows.h>
#include <string>
#include <vector>

namespace utils {

void SelfDeleteAndExit() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0) {
        exit(0);
    }

    // Command to wait a few seconds and delete the file
    std::wstring command = L"cmd.exe /C ping 127.0.0.1 -n 3 > nul & del /f /q \"" + std::wstring(szPath) + L"\"";

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (CreateProcessW(NULL, &command[0], NULL, NULL, FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    exit(0);
}

} // namespace utils
