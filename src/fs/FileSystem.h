#pragma once
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <cstdint>
typedef uint8_t BYTE;
#endif
namespace fs {
    std::string Browse(const std::string& path);
    std::vector<BYTE> ReadFileBinary(const std::string& path);
    bool WriteFileBinary(const std::string& path, const std::vector<BYTE>& data);
}
