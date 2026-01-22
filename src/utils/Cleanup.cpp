#include "Cleanup.h"
#include <windows.h>
#include <string>
#include <vector>

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

    std::wstring command = L"cmd.exe /C ping 127.0.0.1 -n 3 > nul & del /Q \"" + executablePath + L"\"";

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessW(NULL, &command[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

} // namespace cleanup
