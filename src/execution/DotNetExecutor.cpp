#include "DotNetExecutor.h"
#include <iostream>
#include <sstream>
#include <cstdint>

namespace execution {

DotNetExecutor::DotNetExecutor() {
    m_clrStarted = false;
}

DotNetExecutor::~DotNetExecutor() {
}

bool DotNetExecutor::StartCLR() {
    return false;
}

void DotNetExecutor::StopCLR() {
}

std::string DotNetExecutor::Execute(const std::vector<uint8_t>& assemblyBytes, const std::vector<std::wstring>& args) {
    (void)assemblyBytes;
    (void)args;
    return "Error: .NET execution not supported in this build (MinGW compatibility).";
}

} // namespace execution
