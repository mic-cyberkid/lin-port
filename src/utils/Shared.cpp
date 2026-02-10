#ifdef _WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <sddl.h>
#include <tlhelp32.h>
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#else
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

#include "Shared.h"
#include <vector>
#include <sstream>
#include <iomanip>

namespace utils {

std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return "";
#ifdef _WIN32
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
#else
    std::string s;
    for (wchar_t wc : wstr) s += (char)wc;
    return s;
#endif
}

std::wstring s2ws(const std::string& str) {
    if (str.empty()) return L"";
#ifdef _WIN32
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
#else
    std::wstring ws;
    for (char c : str) ws += (wchar_t)c;
    return ws;
#endif
}

std::wstring GetCurrentUserSid() {
#ifdef _WIN32
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
#else
    return L"S-1-5-linux";
#endif
}

bool IsAdmin() {
#ifdef _WIN32
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
#else
    return geteuid() == 0;
#endif
}

bool ImpersonateLoggedOnUser() {
#ifdef _WIN32
    return false; // Stub
#else
    return true;
#endif
}

void RevertToSelf() {
#ifdef _WIN32
    ::RevertToSelf();
#endif
}

namespace Shared {

#ifdef _WIN32
LONG NtCreateKeyRelative(HANDLE hParent, const std::wstring& relativePath, PHANDLE phKey) {
    (void)hParent; (void)relativePath; (void)phKey;
    return 0;
}
#endif

std::string ToHex(unsigned long long val) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << val;
    return ss.str();
}

} // namespace Shared
} // namespace utils
