#pragma once
#include <string>

namespace lateral {

/**
 * TaskExec: Remote Command Execution via Task Scheduler API.
 * Creates a one-time scheduled task on the target machine and runs it immediately.
 */
std::string TaskExec(const std::string& target, const std::string& user, const std::string& pass, const std::string& cmd);

} // namespace lateral
