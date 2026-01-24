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

}
