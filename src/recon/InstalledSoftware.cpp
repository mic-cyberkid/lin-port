#include "InstalledSoftware.h"
#include <unistd.h>
#include "../utils/Exec.h"
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>

namespace recon {
    std::string getInstalledSoftware() {
        nlohmann::json result = nlohmann::json::array();
        if (access("/usr/bin/dpkg-query", X_OK) == 0) {
            std::string out = utils::RunCommand("dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Installed-Size}\n'");
            std::istringstream iss(out); std::string line;
            while (std::getline(iss, line)) {
                std::istringstream lss(line); std::string name, ver, pub, sz;
                std::getline(lss, name, '|'); std::getline(lss, ver, '|'); std::getline(lss, pub, '|'); std::getline(lss, sz);
                result.push_back({{"DisplayName", name}, {"DisplayVersion", ver}, {"Publisher", pub}, {"SizeMB", sz}});
            }
        } else if (access("/usr/bin/rpm", X_OK) == 0) {
            std::string output = utils::RunCommand("rpm -qa --qf '%{NAME}|%{VERSION}|%{VENDOR}|%{SIZE}\n'");
            std::istringstream iss(output); std::string line;
            while (std::getline(iss, line)) {
                 std::istringstream lss(line); std::string name, version, publisher, size;
                std::getline(lss, name, '|'); std::getline(lss, version, '|'); std::getline(lss, publisher, '|'); std::getline(lss, size);
                result.push_back({{"DisplayName", name}, {"DisplayVersion", version}, {"Publisher", publisher}, {"SizeMB", std::to_string(std::atoll(size.c_str()) / 1024 / 1024)}});
            }
        }
        return result.dump();
    }
}
