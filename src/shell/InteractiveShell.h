#pragma once
#include <string>
#include <functional>

namespace shell {
    using ShellCallback = std::function<void(const std::string& output)>;

    void StartShell(ShellCallback callback);
    void StopShell();
    void WriteToShell(const std::string& cmd);
    bool IsShellRunning();
}
