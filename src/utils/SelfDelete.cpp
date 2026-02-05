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

    LOG_INFO("Attempting reliable self-delete...");

    // 1. Rename the file to a random stream (ADS) to bypass some locks/detection
    std::wstring dsName = L":ds";
    std::wstring fullDsPath = std::wstring(szPath) + dsName;

    // Use SetFileInformationByHandle for modern delete-on-close
    HANDLE hFile = CreateFileW(szPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        FILE_DISPOSITION_INFO disp;
        disp.DeleteFile = TRUE;
        if (SetFileInformationByHandle(hFile, FileDispositionInfo, &disp, sizeof(disp))) {
            LOG_INFO("Self-delete marked via FileDispositionInfo.");
        }
        CloseHandle(hFile);
    }

    // Fallback: the classic cmd /c ping & del
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
