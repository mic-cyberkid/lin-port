#pragma once
#include <windows.h>
#include <map>
#include <string>
#include <vector>
#include <winternl.h>

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

// Syscall prototypes
extern "C" NTSTATUS NtCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG TitleIndex,
    IN PUNICODE_STRING Class,
    IN ULONG CreateOptions,
    OUT PULONG Disposition
);

extern "C" NTSTATUS NtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex,
    IN ULONG Type,
    IN PVOID Data,
    IN ULONG DataSize
);

unsigned long djb2Hash(const char* str);
FARPROC getProcByHash(HMODULE hModule, unsigned long targetHash);

extern "C" NTSTATUS NtClose(
    IN HANDLE Handle
);
