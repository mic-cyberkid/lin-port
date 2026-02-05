#pragma once
#include <string>

namespace evasion {

class UACBypass {
public:
    static bool Execute(const std::wstring& command);

private:
    static bool Fodhelper(const std::wstring& command);
    static bool Eventvwr(const std::wstring& command);
    static bool Cmstp(const std::wstring& command);
};

} // namespace evasion
