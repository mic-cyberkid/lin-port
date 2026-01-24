#pragma once
#include <windows.h>
#include <vector>
#include <string>

namespace credential {

class LsassDumper {
public:
    // Captures a memory dump of lsass.exe and returns it as a byte vector
    static std::vector<BYTE> Dump();

private:
    static bool EnableDebugPrivilege();
    static DWORD GetLsassPid();
};

} // namespace credential
