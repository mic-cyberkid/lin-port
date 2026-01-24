#pragma once
#include <windows.h>

namespace evasion {

class Unhooker {
public:
    // Refreshes the .text section of ntdll.dll from its disk version
    static bool RefreshNtdll();

private:
    static PVOID GetNtdllFromDisk();
};

} // namespace evasion
