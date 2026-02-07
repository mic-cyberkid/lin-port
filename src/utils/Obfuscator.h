#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace utils {

    inline std::wstring xor_wstr(const wchar_t* str, size_t len) {
        std::wstring out(str, len);
        const uint8_t key[] = { 0x4B, 0x1F, 0x8C, 0x3E };
        for (size_t i = 0; i < len; i++) out[i] ^= (wchar_t)key[i % 4];
        return out;
    }

    inline std::string xor_str(const char* str, size_t len) {
        std::string out(str, len);
        const uint8_t key[] = { 0x4B, 0x1F, 0x8C, 0x3E };
        for (size_t i = 0; i < len; i++) out[i] ^= (char)key[i % 4];
        return out;
    }

    // Enhanced XOR routine to bypass simple pattern matching
    // Uses a multi-byte rolling key to break static signatures
    inline std::wstring DecryptW(const wchar_t* enc, size_t len) {
        std::wstring out;
        out.reserve(len);
        // Multi-byte key: 0x4B, 0x1F, 0x8C, 0x3E
        const uint8_t key[] = { 0x4B, 0x1F, 0x8C, 0x3E };
        for (size_t i = 0; i < len; i++) {
            out += (wchar_t)(enc[i] ^ (wchar_t)key[i % 4]);
        }
        return out;
    }

    inline std::string DecryptA(const std::string& enc) {
        std::string out = enc;
        const uint8_t key[] = { 0x4B, 0x1F, 0x8C, 0x3E };
        for (size_t i = 0; i < out.length(); i++) {
            out[i] ^= (char)key[i % 4];
        }
        return out;
    }
}
