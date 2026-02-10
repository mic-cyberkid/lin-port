#pragma once
#include <vector>
#include <string>
#include <cstdint>
namespace execution {
    std::string ExecuteInMemory(const std::vector<uint8_t>& elfData, const std::string& args);
}
