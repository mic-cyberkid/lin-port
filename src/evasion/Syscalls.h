#pragma once
#include <windows.h>
#include <map>
#include <string>
#include <vector>

namespace evasion {

struct SyscallStub {
    DWORD ssn;
    PVOID address;
};

class SyscallResolver {
public:
    static SyscallResolver& GetInstance();

    // Resolves a syscall by name (e.g., "NtAllocateVirtualMemory")
    DWORD GetServiceNumber(const std::string& functionName);

    // Gets the address of the 'syscall; ret' gadget in ntdll
    PVOID GetSyscallGadget();

private:
    SyscallResolver();
    void ResolveAll();

    std::map<std::string, DWORD> m_syscallMap;
    PVOID m_syscallGadget = nullptr;
};

// Syscall Wrappers
NTSTATUS SysNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS SysNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
NTSTATUS SysNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
NTSTATUS SysNtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
NTSTATUS SysNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

} // namespace evasion

// Helper for calling syscalls (requires assembly or gadget jump)
// Prototype with maximum expected arguments to ensure caller allocates enough stack space.
extern "C" NTSTATUS InternalDoSyscall(DWORD ssn,
    PVOID a1, PVOID a2, PVOID a3, PVOID a4,
    PVOID a5, PVOID a6, PVOID a7, PVOID a8,
    PVOID a9, PVOID a10, PVOID a11);
