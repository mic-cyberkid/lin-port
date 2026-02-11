#include "AntiSandbox.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/ptrace.h>
#endif
namespace evasion {
bool IsLikelySandbox() {
#ifdef _WIN32
    MEMORYSTATUSEX mem; mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem) && mem.ullTotalPhys < 0x100000000ULL) return true;
    SYSTEM_INFO si; GetSystemInfo(&si); if (si.dwNumberOfProcessors <= 2) return true;
    if (IsDebuggerPresent()) return true;
    if (GetTickCount64() / 1000 < 180) return true;
#else
    struct sysinfo si; if (sysinfo(&si) == 0) {
        if (si.totalram * si.mem_unit < 4000000000ULL) return true;
    }
    if (sysconf(_SC_NPROCESSORS_ONLN) <= 2) return true;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) return true;
#endif
    return false;
}
}
