#include "SelfDelete.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <cstdio>
#endif
#include <string>
#include <vector>
#include "../utils/Logger.h"

namespace utils {

void SelfDeleteAndExit() {
#ifdef _WIN32
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0) {
        exit(0);
    }
    LOG_INFO("Reliable self-delete.");
    HANDLE hFile = CreateFileW(szPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        FILE_DISPOSITION_INFO disp;
        disp.DeleteFile = TRUE;
        SetFileInformationByHandle(hFile, FileDispositionInfo, &disp, sizeof(disp));
        CloseHandle(hFile);
    }
    std::wstring command = L"cmd.exe /C del /f /q \"" + std::wstring(szPath) + L"\"";
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(NULL, (LPWSTR)command.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    exit(0);
#else
    char result[1024];
    ssize_t count = readlink("/proc/self/exe", result, sizeof(result)-1);
    if (count != -1) {
        result[count] = '\0';
        unlink(result);
    }
    exit(0);
#endif
}

} // namespace utils
