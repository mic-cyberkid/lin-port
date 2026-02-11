#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace recon {

    struct InstalledApp {
        std::string displayName;
        std::string displayVersion;
        std::string publisher;
        std::string installDate;
        std::string installLocation;
        std::string sizeMB;
        std::string quietUninstallString;
    };

    std::string getInstalledSoftware();

} // namespace recon
