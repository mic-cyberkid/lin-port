#pragma once

#include <vector>
#include <windows.h>

namespace crypto {

// Decrypts DPAPI-protected data (CryptUnprotectData)
std::vector<BYTE> decryptDpapi(const std::vector<BYTE>& data);

} // namespace crypto
