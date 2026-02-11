#include "WifiScanner.h"
#include <string>
#include <vector>
#include "../utils/Exec.h"

namespace wifi {
    std::string scanAvailableWifi() {
#ifdef LINUX
        // Try nmcli or iwlist
        std::string output = utils::RunCommand("nmcli -t -f SSID,SIGNAL,SECURITY device wifi list 2>/dev/null");
        if (output.empty()) {
            output = utils::RunCommand("iwlist wlan0 scanning 2>/dev/null | grep ESSID");
        }
        return output;
#else
        return "Not supported";
#endif
    }
}
