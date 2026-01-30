#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace execution {

class DotNetExecutor {
public:
    DotNetExecutor();
    ~DotNetExecutor();

    // Executes a .NET assembly from memory and returns its console output
    std::string Execute(const std::vector<uint8_t>& assemblyBytes, const std::vector<std::wstring>& args);

private:
    bool StartCLR();
    void StopCLR();

    bool m_clrStarted = false;
};

} // namespace execution
