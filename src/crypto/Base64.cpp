#include "Base64.h"
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

namespace crypto {

    std::string Base64Encode(const std::vector<BYTE>& data) {
        if (data.empty()) return "";

        DWORD len = 0;
        // CRYPT_STRING_BASE64_NOCR encodes without headers/newlines
        if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len)) {
            return "";
        }

        std::string result(len, '\0');
        if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &len)) {
            return "";
        }
        
        // Remove null terminator if present
        if (!result.empty() && result.back() == '\0') result.pop_back();
        return result;
    }

    std::vector<BYTE> Base64Decode(const std::string& data) {
        if (data.empty()) return {};

        DWORD len = 0;
        if (!CryptStringToBinaryA(data.c_str(), (DWORD)data.length(), CRYPT_STRING_BASE64, NULL, &len, NULL, NULL)) {
            return {};
        }

        std::vector<BYTE> result(len);
        if (!CryptStringToBinaryA(data.c_str(), (DWORD)data.length(), CRYPT_STRING_BASE64, result.data(), &len, NULL, NULL)) {
            return {};
        }

        return result;
    }

}
