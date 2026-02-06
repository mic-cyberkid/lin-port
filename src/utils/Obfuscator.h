#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace utils {

    inline std::wstring xor_wstr(const wchar_t* str, size_t len, wchar_t key = 0x5A) {
        std::wstring out(str, len);
        for (auto& c : out) c ^= key;
        return out;
    }

    inline std::string xor_str(const char* str, size_t len, char key = 0x5A) {
        std::string out(str, len);
        for (auto& c : out) c ^= key;
        return out;
    }

    // Enhanced XOR routine to bypass simple pattern matching
    inline std::wstring DecryptW(const wchar_t* enc, size_t len) {
        std::wstring out;
        out.reserve(len);
        for (size_t i = 0; i < len; i++) {
            // A dynamic-looking key derivation
            uint32_t a = 0xBE;
            uint32_t b = 0xEF;
            uint32_t key = (a ^ b) & 0xFF; // 0x51
            key |= 0x0B; // 0x5B
            key ^= 0x01; // 0x5A
            out += (wchar_t)(enc[i] ^ (wchar_t)key);
        }
        return out;
    }

    inline std::string DecryptA(const std::string& enc) {
        std::string out = enc;
        for (auto& c : out) {
            char k = (char)(0x3A | 0x60); // 0x7A
            k &= 0x5F; // 0x5A
            c ^= k;
        }
        return out;
    }
}
