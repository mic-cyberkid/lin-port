#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace utils {

    // Simple XOR obfuscator for strings
    template<size_t N>
    struct ObfString {
        char data[N];
        static constexpr uint8_t key = 0xAA;

        constexpr ObfString(const char* str) {
            for (size_t i = 0; i < N; ++i) data[i] = str[i] ^ key;
        }

        std::string decrypt() const {
            std::string s;
            for (size_t i = 0; i < N - 1; ++i) s += (char)(data[i] ^ key);
            return s;
        }
    };

    #define OBF(str) []() { static constexpr utils::ObfString<sizeof(str)> obf(str); return obf.decrypt(); }()

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

    inline std::wstring DecryptW(const wchar_t* enc, size_t len) {
        return xor_wstr(enc, len);
    }

    inline std::string DecryptA(const std::string& enc) {
        std::string out = enc;
        const uint8_t key[] = { 0x4B, 0x1F, 0x8C, 0x3E };
        for (size_t i = 0; i < out.length(); i++) out[i] ^= (char)key[i % 4];
        return out;
    }
}
