#pragma once
#include <string>
#include <windows.h>

namespace utils {
    std::string ws2s(const std::wstring& wstr);
    std::wstring s2ws(const std::string& str);
    std::wstring GetCurrentUserSid();

    namespace Shared {
        std::string ToHex(unsigned int value);
    }
}
