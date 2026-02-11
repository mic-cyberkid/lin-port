#pragma once
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
typedef void* HANDLE;
typedef HANDLE* PHANDLE;
typedef long LONG;
#define LPCWSTR const wchar_t*
#define BOOL bool
#define TRUE true
#define FALSE false
#endif

namespace utils {
    std::string ws2s(const std::wstring& wstr);
    std::wstring s2ws(const std::string& str);
    std::wstring GetCurrentUserSid();
    bool IsAdmin();
    bool ImpersonateLoggedOnUser();
    void RevertToSelf();

    namespace Shared {
        std::string ToHex(unsigned long long value);
#ifdef _WIN32
        LONG NtCreateKeyRelative(HANDLE hRoot, const std::wstring& relativePath, PHANDLE hTarget);
#endif
    }
}
