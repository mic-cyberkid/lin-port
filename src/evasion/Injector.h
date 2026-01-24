#pragma once
#include <windows.h>
#include <vector>

namespace evasion {

class Injector {
public:
    // Performs Process Hollowing by spawning a suspended process and replacing its memory
    static bool HollowProcess(const char* targetPath, const std::vector<uint8_t>& payload);

    // Performs Module Stomping (overwriting a legitimate module's .text in a remote process)
    static bool ModuleStomping(DWORD processId, const char* moduleName, const std::vector<uint8_t>& payload);
};

} // namespace evasion
