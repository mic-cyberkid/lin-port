#include "SysInfo.h"
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <fstream>
#include <regex>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <time.h>

namespace recon {

bool IsUserAdmin() {
    return geteuid() == 0;
}

std::string GetMachineGuid() {
    std::ifstream f("/etc/machine-id");
    if (!f.is_open()) f.open("/var/lib/dbus/machine-id");
    std::string id;
    if (f >> id) return id;
    return "unknown";
}

std::string getSysInfo() {
    nlohmann::json info;
    info["collected_at"] = [](){
        time_t now = time(0); char buf[80]; struct tm t;
        localtime_r(&now, &t);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &t);
        return std::string(buf);
    }();
    info["is_admin"] = IsUserAdmin();
    info["machine_guid"] = GetMachineGuid();

    struct utsname un;
    if (uname(&un) == 0) {
        info["os_caption"] = std::string(un.sysname) + " " + un.release;
        info["os_build"] = un.version;
        info["architecture"] = un.machine;
        info["hostname"] = un.nodename;
    }
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info["uptime_seconds"] = si.uptime;
        info["total_physical_memory_gb"] = si.totalram * si.mem_unit / (1024 * 1024 * 1024);
    }
    info["current_user"] = getlogin() ? getlogin() : "unknown";

    return info.dump();
}
}
