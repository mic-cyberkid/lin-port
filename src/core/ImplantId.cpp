#include "ImplantId.h"
#include <unistd.h>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

namespace core {

std::string getMachineGuid() {
    std::ifstream idFile("/etc/machine-id");
    if (!idFile.is_open()) {
        idFile.open("/var/lib/dbus/machine-id");
    }
    if (idFile.is_open()) {
        std::string id;
        idFile >> id;
        return id;
    }
    return "";
}

std::string generateNewGuid() {
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom.is_open()) {
        unsigned char buf[16];
        urandom.read(reinterpret_cast<char*>(buf), 16);
        std::stringstream ss;
        for (int i = 0; i < 16; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
            if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
        }
        return ss.str();
    }
    return "unknown-implant-id";
}

std::string generateImplantId() {
    std::string machineGuid = getMachineGuid();
    if (!machineGuid.empty()) {
        return machineGuid;
    }
    return generateNewGuid();
}

} // namespace core
