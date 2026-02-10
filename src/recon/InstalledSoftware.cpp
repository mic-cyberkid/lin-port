#include "InstalledSoftware.h"
#ifndef LINUX
#include <windows.h>
#else
#include <unistd.h>
#include "../utils/Exec.h"
#endif
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include "../external/nlohmann/json.hpp"
namespace recon {
    std::string getInstalledSoftware() {
#ifdef LINUX
        nlohmann::json result = nlohmann::json::array();
        if (access("/usr/bin/dpkg-query", X_OK) == 0) {
            std::string out = utils::RunCommand("dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Installed-Size}\n'");
            std::istringstream iss(out); std::string line;
            while (std::getline(iss, line)) {
                std::istringstream lss(line); std::string name, ver, pub, sz;
                std::getline(lss, name, '|'); std::getline(lss, ver, '|'); std::getline(lss, pub, '|'); std::getline(lss, sz);
                result.push_back({{"DisplayName", name}, {"DisplayVersion", ver}, {"Publisher", pub}, {"SizeMB", sz}});
            }
        }
        return result.dump();
#else
        return "[]";
#endif
    }
}
