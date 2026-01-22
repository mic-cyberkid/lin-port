#include "Cleanup.h"
#include <windows.h>
#include <vector>
#include "Logger.h"

namespace utils {

void Cleanup::SelfDelete() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0) {
        LOG_ERROR("Cleanup: Failed to get module file name.");
        return;
    }

    // Command to delete the file after a short delay
    // Use cmd.exe to perform the deletion so the process can exit
    std::wstring command = L"cmd.exe /c timeout /t 3 & del /f /q \"" + std::wstring(szPath) + L"\"";
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    // We start cmd.exe as a hidden process
    BOOL success = CreateProcessW(
        NULL,
        &command[0],
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success) {
        LOG_INFO("Cleanup: Self-deletion scheduled.");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        // The calling application should exit shortly after this
    } else {
        LOG_ERROR("Cleanup: Failed to schedule self-deletion.");
    }
}

} // namespace utils
