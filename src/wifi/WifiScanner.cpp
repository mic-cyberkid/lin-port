#include "WifiScanner.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include "../utils/Logger.h"

namespace wifi {
    std::string scanAvailableWifi() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return "Socket error";

        struct iwreq wrq;
        std::memset(&wrq, 0, sizeof(wrq));
        std::strncpy(wrq.ifr_name, "wlan0", IFNAMSIZ);

        // First, trigger a scan
        if (ioctl(sock, SIOCSIWSCAN, &wrq) < 0) {
            // Might need root, or interface name might be different
            // Try common names
            const char* interfaces[] = {"wlp2s0", "wlp3s0", "wlan1", "eth0"};
            bool success = false;
            for (const char* iface : interfaces) {
                std::strncpy(wrq.ifr_name, iface, IFNAMSIZ);
                if (ioctl(sock, SIOCSIWSCAN, &wrq) >= 0) {
                    success = true;
                    break;
                }
            }
            if (!success) {
                close(sock);
                return "Failed to trigger scan (root required?)";
            }
        }

        // Wait for scan to complete (simplified)
        sleep(2);

        // Get results
        char buffer[4096];
        wrq.u.data.pointer = buffer;
        wrq.u.data.length = sizeof(buffer);
        wrq.u.data.flags = 0;

        std::string report = "WIFI_SCAN_RESULTS:\n";
        if (ioctl(sock, SIOCGIWSCAN, &wrq) >= 0) {
            // Parse results (simplified parsing of iw_event stream)
            int pos = 0;
            while (pos < wrq.u.data.length) {
                struct iw_event* event = (struct iw_event*)(buffer + pos);
                if (event->len <= 0) break;

                if (event->cmd == SIOCGIWESSID) {
                    char essid[IW_ESSID_MAX_SIZE + 1];
                    std::memset(essid, 0, sizeof(essid));
                    std::memcpy(essid, buffer + pos + sizeof(struct iw_event), event->u.essid.length);
                    report += "SSID: " + std::string(essid) + "\n";
                }
                pos += event->len;
            }
        } else {
            report += "Failed to get scan results";
        }

        close(sock);
        return report;
    }
}
