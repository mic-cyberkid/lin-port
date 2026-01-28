#include "AntiSandbox.h"
#include <windows.h>

namespace evasion {

bool IsLikelySandbox() {
    // 1. Very low memory (most sandboxes < 4 GB)
    MEMORYSTATUSEX mem = { sizeof(mem) };
    if (GlobalMemoryStatusEx(&mem) && mem.ullTotalPhys < 0x100000000ULL) // < 4GB
        return true;

    // 2. Single / two cores (very common in analysis VMs)
    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 2) return true;

    // 3. Debugger present (many sandboxes attach)
    if (IsDebuggerPresent()) return true;

    // 4. Very recent boot (sandboxes often reboot images)
    ULONGLONG uptime = GetTickCount64() / 1000;
    if (uptime < 180) return true; // < 3 minutes

    return false;
}

} // namespace evasion
