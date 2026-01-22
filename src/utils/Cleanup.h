#pragma once

#include <string>

namespace utils {

class Cleanup {
public:
    /**
     * @brief Schedules the current executable for deletion using a delayed command-line process.
     * This is typically used after persistence has been established and we want to remove the 
     * original "dropper" file.
     */
    static void SelfDelete();
};

} // namespace utils
