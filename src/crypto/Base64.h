#pragma once
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <cstdint>
typedef uint8_t BYTE;
#endif

namespace crypto {
    std::string Base64Encode(const std::vector<BYTE>& data);
    std::vector<BYTE> Base64Decode(const std::string& data);
}
