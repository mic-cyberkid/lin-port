#pragma once
#include <string>
#include <vector>
#include <windows.h>

namespace fs {
    std::string Browse(const std::string& path);
    std::vector<BYTE> ReadFileBinary(const std::string& path);
    bool WriteFileBinary(const std::string& path, const std::vector<BYTE>& data);
}
