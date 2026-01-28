#pragma once
#include <string>

namespace lateral {
    std::string WmiExec(const std::string& target, const std::string& user, const std::string& pass, const std::string& cmd);
}
