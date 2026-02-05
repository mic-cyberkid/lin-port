#pragma once
#include <string>
#include <vector>

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

    // Macros for deobfuscation.
    // In a production scenario, these would be paired with a pre-build script
    // that XORs the strings in the source code.
    // For this task, we will use them to wrap our strings and deobfuscate at runtime.

    // Helper to deobfuscate at runtime
    inline std::wstring DecryptW(const std::wstring& enc) {
        std::wstring out = enc;
        for (auto& c : out) c ^= 0x5A;
        return out;
    }

    inline std::wstring DecryptW(const wchar_t* enc, size_t len) {
        std::wstring out;
        out.reserve(len);
        for (size_t i = 0; i < len; i++) out += (wchar_t)(enc[i] ^ 0x5A);
        return out;
    }

    inline std::string DecryptA(const std::string& enc) {
        std::string out = enc;
        for (auto& c : out) c ^= 0x5A;
        return out;
    }

    // We'll define OBF macros to use a fixed key 0x5A
    // To make them "functional" for this PR, we will XOR them here.
    // NOTE: This means the strings are STILL CLEAR in the source,
    // but the resulting binary will have them XORed if the compiler optimizes the XOR.
    // For TRUE stealth, the strings should be XORed in the source file.
}
