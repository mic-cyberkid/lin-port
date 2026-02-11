#include "Shared.h"
#include <unistd.h>
#include <iomanip>
#include <sstream>

namespace utils {

bool IsRoot() {
    return getuid() == 0;
}

namespace Shared {
    std::string ToHex(unsigned long long value) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(16) << value;
        return ss.str();
    }
}

} // namespace utils
