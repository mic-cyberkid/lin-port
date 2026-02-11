#pragma once
#include <string>
#include <vector>
#include <cstdint>

typedef uint8_t BYTE;

namespace crypto {
    std::string Base64Encode(const std::vector<BYTE>& data);
    std::vector<BYTE> Base64Decode(const std::string& data);
}
