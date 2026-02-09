#pragma once
#include <string>

namespace lateral {

/**
 * SvcExec: Remote Command Execution via Service Control Manager (SCM).
 * Similar to PsExec, it creates a temporary service on the target machine.
 */
std::string SvcExec(const std::string& target, const std::string& user, const std::string& pass, const std::string& cmd);

} // namespace lateral
