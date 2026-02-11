#include "ImplantId.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fstream>
#endif
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

namespace core {

std::string getMachineGuid() {
#ifdef _WIN32
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
#else
    std::ifstream idFile("/etc/machine-id");
    if (!idFile.is_open()) {
        idFile.open("/var/lib/dbus/machine-id");
    }
    if (idFile.is_open()) {
        std::string id;
        idFile >> id;
        return id;
    }
#endif
    return "";
}

std::string generateNewGuid() {
#ifdef _WIN32
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
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom.is_open()) {
        unsigned char buf[16];
        urandom.read(reinterpret_cast<char*>(buf), 16);
        std::stringstream ss;
        for (int i = 0; i < 16; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
            if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
        }
        return ss.str();
    }
#endif
    return "unknown-implant-id";
}

std::string generateImplantId() {
    std::string machineGuid = getMachineGuid();
    if (!machineGuid.empty()) {
        return machineGuid;
    }
    return generateNewGuid();
}

} // namespace core
