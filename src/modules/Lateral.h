#pragma once

#include <string>

namespace Lateral {
    bool WmiRemoteExec(const std::wstring& target, const std::wstring& cmd);
}
