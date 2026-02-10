#include "DeepRecon.h"
#include <nlohmann/json.hpp>
#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <comdef.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#endif
#include <vector>
#include <iostream>
#include <iomanip>

namespace recon {

#ifndef LINUX
    // Windows implementation (omitted for brevity in this rewrite)
#endif

    std::string GetDeepRecon() {
        nlohmann::json reconData;
#ifdef LINUX
        // Simple ARP table from /proc/net/arp
        nlohmann::json arpList = nlohmann::json::array();
        std::ifstream arpFile("/proc/net/arp");
        std::string line;
        std::getline(arpFile, line); // Skip header
        while (std::getline(arpFile, line)) {
            std::istringstream iss(line);
            std::string ip, hw, flags, mac, mask, dev;
            if (iss >> ip >> hw >> flags >> mac >> mask >> dev) {
                nlohmann::json entry;
                entry["ip"] = ip;
                entry["mac"] = mac;
                entry["dev"] = dev;
                arpList.push_back(entry);
            }
        }
        reconData["arp_table"] = arpList;

        // Simple security product check
        nlohmann::json security = nlohmann::json::array();
        std::vector<std::string> scanners = {"clamav", "rkhunter", "chkrootkit", "lynis"};
        for (const auto& s : scanners) {
            if (access(("/usr/bin/" + s).c_str(), X_OK) == 0) security.push_back(s);
        }
        reconData["security_products"] = security;
#else
        // Windows recon
#endif
        return reconData.dump(4);
    }

}
