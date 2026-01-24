#pragma once
#include <string>
#include <vector>
#include <windows.h>

namespace crypto {
    std::string Base64Encode(const std::vector<BYTE>& data);
    std::vector<BYTE> Base64Decode(const std::string& data);
}
