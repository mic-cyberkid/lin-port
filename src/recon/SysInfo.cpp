#include "SysInfo.h"
#ifndef LINUX
#include "WmiHelpers.h"
#include <windows.h>
#include <shlobj.h>
#else
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <fstream>
#include <regex>
#endif
#include "../external/nlohmann/json.hpp"
#include <string>
#include <vector>
#include <time.h>
namespace recon {
#ifndef LINUX
bool IsUserAdmin() { return false; }
std::string GetMachineGuid() { return "unknown"; }
#else
bool IsUserAdmin() { return geteuid() == 0; }
std::string GetMachineGuid() { std::ifstream f("/etc/machine-id"); std::string id; if (f >> id) return id; return "unknown"; }
#endif
std::string getSysInfo() {
    nlohmann::json info;
    info["collected_at"] = [](){
        time_t now = time(0); char buf[80]; struct tm t;
#ifdef _WIN32
        localtime_s(&t, &now);
#else
        localtime_r(&now, &t);
#endif
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &t);
        return std::string(buf);
    }();
    info["is_admin"] = IsUserAdmin();
    info["machine_guid"] = GetMachineGuid();
#ifdef LINUX
    struct utsname un; if (uname(&un) == 0) {
        info["os_caption"] = std::string(un.sysname) + " " + un.release;
        info["os_build"] = un.version;
        info["architecture"] = un.machine;
        info["hostname"] = un.nodename;
    }
    struct sysinfo si; if (sysinfo(&si) == 0) {
        info["uptime_seconds"] = si.uptime;
        info["total_physical_memory_gb"] = si.totalram * si.mem_unit / (1024 * 1024 * 1024);
    }
    info["current_user"] = getlogin() ? getlogin() : "unknown";
#endif
    return info.dump();
}
}
