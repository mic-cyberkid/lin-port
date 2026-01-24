#include "ImplantId.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>

#include <vector>

namespace core {

std::string getMachineGuid() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD size = 0;
        if (RegQueryValueExW(hKey, L"MachineGuid", NULL, NULL, NULL, &size) == ERROR_SUCCESS) {
            std::vector<wchar_t> value(size / sizeof(wchar_t));
            if (RegQueryValueExW(hKey, L"MachineGuid", NULL, NULL, (LPBYTE)value.data(), &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                std::wstring wstr(value.data());
                int len = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.length(), NULL, 0, NULL, NULL);
                std::string r(len, '\0');
                WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.length(), &r[0], len, NULL, NULL);
                return r;
            }
        }
        RegCloseKey(hKey);
    }
    return "";
}

std::string generateNewGuid() {
    GUID guid;
    if (CoCreateGuid(&guid) == S_OK) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0')
           << std::setw(8) << guid.Data1 << "-"
           << std::setw(4) << guid.Data2 << "-"
           << std::setw(4) << guid.Data3 << "-"
           << std::setw(2) << (int)guid.Data4[0]
           << std::setw(2) << (int)guid.Data4[1] << "-"
           << std::setw(2) << (int)guid.Data4[2]
           << std::setw(2) << (int)guid.Data4[3]
           << std::setw(2) << (int)guid.Data4[4]
           << std::setw(2) << (int)guid.Data4[5]
           << std::setw(2) << (int)guid.Data4[6]
           << std::setw(2) << (int)guid.Data4[7];
        return ss.str();
    }
    return "";
}

std::string generateImplantId() {
    std::string machineGuid = getMachineGuid();
    if (!machineGuid.empty()) {
        return machineGuid;
    }
    // Fallback to generating a new GUID
    return generateNewGuid();
}

} // namespace core
