#pragma once
#include <string>
#include <vector>

namespace utils {

    // Simple XOR obfuscator for strings
    // Key is hardcoded for simplicity in this version
    inline std::string Obfuscate(const std::string& input) {
        std::string output = input;
        char key = 0x42; 
        for (size_t i = 0; i < input.size(); i++) {
            output[i] = input[i] ^ key;
        }
        return output;
    }

    // Since we want to obfuscate literals and decrypt at runtime, 
    // we'll use this helper.
    inline std::string Deobfuscate(const std::string& input) {
        return Obfuscate(input); // XOR is symmetric
    }

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

    // OBF macros for runtime deobfuscation.
    // For now, these are identity to ensure functionality,
    // but can be updated to use xor_wstr/xor_str when literals are pre-obfuscated.
    #define OBF_W(str) std::wstring(L##str)
    #define OBF_A(str) std::string(str)

}
