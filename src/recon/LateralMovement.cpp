#include "LateralMovement.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <pwd.h>
#include <vector>

namespace recon {

namespace fs = std::filesystem;

std::string LateralMovement::RunLateralRecon() {
    std::stringstream ss;
    ss << "--- LATERAL MOVEMENT RECON ---\n\n";

    ss << "[+] SSH Keys Found:\n";
    auto keys = GetSSHKeys();
    for (const auto& key : keys) {
        ss << "  Path: " << key.path << " (" << key.type << ")\n";
        // We only show first line of private keys for the report to be concise
        if (key.type == "private") {
            size_t firstLine = key.content.find('\n');
            ss << "  Preview: " << (firstLine != std::string::npos ? key.content.substr(0, firstLine) : "...") << "\n";
        }
    }
    ss << "\n";

    ss << "[+] Potential Targets:\n";
    auto targets = GetTargets();
    for (const auto& target : targets) {
        ss << "  Target: " << target.hostname << " (Source: " << target.source << ")\n";
    }
    ss << "\n";

    ss << "[+] SSH Agent:\n";
    ss << "  " << GetSSHAgentInfo() << "\n";

    return ss.str();
}

std::vector<SSHKey> LateralMovement::GetSSHKeys() {
    std::vector<SSHKey> keys;
    const char* home = getenv("HOME");
    if (!home) return keys;

    std::string sshDir = std::string(home) + "/.ssh";
    if (!fs::exists(sshDir)) return keys;

    for (const auto& entry : fs::directory_iterator(sshDir)) {
        if (entry.is_regular_file()) {
            std::string filename = entry.path().filename().string();
            std::string path = entry.path().string();

            std::ifstream file(path);
            if (!file.is_open()) continue;

            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            SSHKey key;
            key.path = path;
            key.content = content;

            if (content.find("PRIVATE KEY") != std::string::npos) {
                key.type = "private";
                keys.push_back(key);
            } else if (filename.ends_with(".pub")) {
                key.type = "public";
                keys.push_back(key);
            }
        }
    }
    return keys;
}

std::vector<LateralTarget> LateralMovement::GetTargets() {
    std::vector<LateralTarget> targets;
    const char* home = getenv("HOME");

    // 1. known_hosts
    if (home) {
        std::string khPath = std::string(home) + "/.ssh/known_hosts";
        std::ifstream khFile(khPath);
        if (khFile.is_open()) {
            std::string line;
            while (std::getline(khFile, line)) {
                if (line.empty() || line[0] == '#' || line[0] == '@') continue;
                std::stringstream ls(line);
                std::string hostPart;
                ls >> hostPart;
                // Host part can be comma separated
                std::stringstream hs(hostPart);
                std::string singleHost;
                while (std::getline(hs, singleHost, ',')) {
                    if (singleHost.find('|') == std::string::npos) { // Not hashed
                        targets.push_back({singleHost, "known_hosts"});
                    }
                }
            }
        }
    }

    // 2. /etc/hosts
    std::ifstream hostsFile("/etc/hosts");
    if (hostsFile.is_open()) {
        std::string line;
        while (std::getline(hostsFile, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::stringstream ls(line);
            std::string ip;
            ls >> ip;
            std::string host;
            while (ls >> host) {
                if (host != "localhost" && host != "ip6-localhost" && host != "ip6-loopback") {
                    targets.push_back({host, "/etc/hosts (" + ip + ")"});
                }
            }
        }
    }

    return targets;
}

std::string LateralMovement::GetSSHAgentInfo() {
    const char* agentSock = getenv("SSH_AUTH_SOCK");
    if (agentSock) {
        return "SSH_AUTH_SOCK found at " + std::string(agentSock) + ". Agent hijacking possible.";
    }
    return "SSH_AUTH_SOCK not found.";
}

} // namespace recon
