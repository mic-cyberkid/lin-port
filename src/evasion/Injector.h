#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>

namespace evasion {

class Injector {
public:
    // Process Hollowing
    static bool HollowProcess(const char* targetPath, const std::vector<uint8_t>& payload);

    // Module Stomping
    static bool ModuleStomping(DWORD processId, const char* moduleName, const std::vector<uint8_t>& payload);
};

} // namespace evasion
