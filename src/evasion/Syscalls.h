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

} // namespace evasion

// Helper for calling syscalls (requires assembly or gadget jump)
extern "C" NTSTATUS InternalDoSyscall(DWORD ssn, ...);
