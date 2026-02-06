#pragma once
#include <string>
#include <windows.h>

namespace utils {
    std::string ws2s(const std::wstring& wstr);
    std::wstring s2ws(const std::string& str);
    std::wstring GetCurrentUserSid();
    bool IsAdmin();

    namespace Shared {
        std::string ToHex(unsigned long long value);
        LONG NtCreateKeyRelative(HANDLE hRoot, const std::wstring& relativePath, PHANDLE hTarget);
    }
}
