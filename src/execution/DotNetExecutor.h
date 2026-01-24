#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <metahost.h>

#pragma comment(lib, "mscoree.lib")

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

    ICLRMetaHost* m_pMetaHost = nullptr;
    ICLRRuntimeInfo* m_pRuntimeInfo = nullptr;
    ICorRuntimeHost* m_pRuntimeHost = nullptr;
    bool m_clrStarted = false;
};

} // namespace execution
