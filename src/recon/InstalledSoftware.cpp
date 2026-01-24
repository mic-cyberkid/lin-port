#include "InstalledSoftware.h"
#include <windows.h>
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace recon {

    namespace {
        // Helper to safely get string from registry
        std::string GetRegString(HKEY hKey, const std::wstring& valueName) {
            DWORD dataSize = 0;
            LONG result = RegQueryValueExW(hKey, valueName.c_str(), nullptr, nullptr, nullptr, &dataSize);
            if (result != ERROR_SUCCESS) return "";

            std::vector<wchar_t> buffer(dataSize / sizeof(wchar_t) + 1);
            result = RegQueryValueExW(hKey, valueName.c_str(), nullptr, nullptr, (LPBYTE)buffer.data(), &dataSize);
            if (result != ERROR_SUCCESS) return "";

            // Remove null terminators from the end
            if (!buffer.empty() && buffer.back() == L'\0') {
               buffer.pop_back(); 
            }

            int size_needed = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), (int)buffer.size(), NULL, 0, NULL, NULL);
            std::string strTo(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, buffer.data(), (int)buffer.size(), &strTo[0], size_needed, NULL, NULL);
            return strTo;
        }

        // Helper to get DWORD and convert to string (e.g. for Size)
        std::string GetRegDwordAsString(HKEY hKey, const std::wstring& valueName) {
            DWORD data = 0;
            DWORD dataSize = sizeof(DWORD);
            LONG result = RegQueryValueExW(hKey, valueName.c_str(), nullptr, nullptr, (LPBYTE)&data, &dataSize);
            if (result == ERROR_SUCCESS) {
                return std::to_string(data);
            }
            return "";
        }
    }

    std::string getInstalledSoftware() {
        std::vector<InstalledApp> apps;
        std::vector<std::pair<HKEY, std::wstring>> lookupKeys = {
            {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
            {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
            {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"}
        };

        for (const auto& root : lookupKeys) {
            HKEY hKey;
            if (RegOpenKeyExW(root.first, root.second.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD numSubKeys = 0;
                RegQueryInfoKey(hKey, nullptr, nullptr, nullptr, &numSubKeys, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

                for (DWORD i = 0; i < numSubKeys; ++i) {
                    wchar_t subKeyName[256];
                    DWORD subKeyNameLen = 256;
                    if (RegEnumKeyExW(hKey, i, subKeyName, &subKeyNameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                        HKEY hSubKey;
                        if (RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                            InstalledApp app;
                            app.displayName = GetRegString(hSubKey, L"DisplayName");
                            
                            if (!app.displayName.empty()) {
                                app.displayVersion = GetRegString(hSubKey, L"DisplayVersion");
                                app.publisher = GetRegString(hSubKey, L"Publisher");
                                app.installDate = GetRegString(hSubKey, L"InstallDate");
                                app.installLocation = GetRegString(hSubKey, L"InstallLocation");
                                app.quietUninstallString = GetRegString(hSubKey, L"QuietUninstallString");
                                
                                // Size is often not present or EstimatedSize
                                std::string size = GetRegDwordAsString(hSubKey, L"EstimatedSize");
                                if (!size.empty()) {
                                    try {
                                        double kb = std::stod(size);
                                        std::stringstream ss;
                                        ss << std::fixed << std::setprecision(1) << (kb / 1024.0);
                                        app.sizeMB = ss.str();
                                    } catch (...) {}
                                }
                                
                                // Avoid duplicates
                                bool exists = false;
                                for (const auto& existing : apps) {
                                    if (existing.displayName == app.displayName && existing.displayVersion == app.displayVersion) {
                                        exists = true;
                                        break;
                                    }
                                }
                                
                                if (!exists) {
                                    apps.push_back(app);
                                }
                            }
                            RegCloseKey(hSubKey);
                        }
                    }
                }
                RegCloseKey(hKey);
            }
        }

        // Sort by name
        std::sort(apps.begin(), apps.end(), [](const InstalledApp& a, const InstalledApp& b) {
            std::string nameA = a.displayName;
            std::string nameB = b.displayName;
            std::transform(nameA.begin(), nameA.end(), nameA.begin(), [](unsigned char c){ return (char)::tolower(c); });
            std::transform(nameB.begin(), nameB.end(), nameB.begin(), [](unsigned char c){ return (char)::tolower(c); });
            return nameA < nameB;
        });

        nlohmann::json result = nlohmann::json::array();
        
        // Limit to 100 like Python
        size_t limit = std::min(apps.size(), (size_t)100);
        for (size_t i = 0; i < limit; ++i) {
            result.push_back({
                {"DisplayName", apps[i].displayName},
                {"DisplayVersion", apps[i].displayVersion},
                {"Publisher", apps[i].publisher},
                {"InstallDate", apps[i].installDate},
                {"InstallLocation", apps[i].installLocation},
                {"SizeMB", apps[i].sizeMB}
            });
        }
        
        if (apps.size() > 100) {
             result.push_back({
                {"DisplayName", "[Truncated]"},
                {"SizeMB", "... and " + std::to_string(apps.size() - 100) + " more applications"}
            });
        }

        return result.dump();
    }

} // namespace recon
