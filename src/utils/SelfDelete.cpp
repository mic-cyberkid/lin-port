#include "SelfDelete.h"
#include <unistd.h>
#include <cstdio>
#include <string>
#include <vector>
#include "../utils/Logger.h"

namespace utils {

void SelfDeleteAndExit() {
    char result[1024];
    ssize_t count = readlink("/proc/self/exe", result, sizeof(result)-1);
    if (count != -1) {
        result[count] = '\0';
        unlink(result);
    }
    exit(0);
}

} // namespace utils
