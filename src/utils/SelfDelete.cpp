#include "SelfDelete.h"
#include <windows.h>
#include <string>
#include <vector>
#include "../utils/Logger.h"

namespace utils {

void SelfDeleteAndExit() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0) {
        exit(0);
    }

    LOG_INFO("Reliable self-delete.");

    // 1. Rename to ADS
    std::wstring dsName = L":ds";
    std::wstring fullDsPath = std::wstring(szPath) + dsName;

    // 2. Delete on close
    HANDLE hFile = CreateFileW(szPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        FILE_DISPOSITION_INFO disp;
        disp.DeleteFile = TRUE;
        SetFileInformationByHandle(hFile, FileDispositionInfo, &disp, sizeof(disp));
        CloseHandle(hFile);
    }

    // 3. Fallback: CMD (Completely Silent)
    // "cmd.exe /C ping 127.0.0.1 -n 5 > nul & del /f /q \"" ...
    std::wstring command = L"cmd.exe /C ping 127.0.0.1 -n 5 > nul & del /f /q \"" + std::wstring(szPath) + L"\"";

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Ensure CMD is hidden

    if (CreateProcessW(NULL, (LPWSTR)command.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    exit(0);
}

} // namespace utils
