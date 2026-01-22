#pragma once

#include <string>

namespace recon {

class Decoy {
public:
    /**
     * @brief Launches a decoy document to distract the user.
     * In a real scenario, this would extract a resource to disk.
     * For this simulation, it will create a dummy document and open it.
     */
    static void Launch();

private:
    static std::wstring GetTempPathForDecoy();
    static bool CreateDummyDocument(const std::wstring& path);
};

} // namespace recon
