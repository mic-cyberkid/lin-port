#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace utils {
    // Utility functions for Linux implant
    bool IsRoot();

    namespace Shared {
        std::string ToHex(unsigned long long value);
    }
}
