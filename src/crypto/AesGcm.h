#pragma once

#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#include <cstdint>
typedef uint8_t BYTE;
#endif

namespace crypto {

class AesGcm {
public:
    AesGcm(const std::vector<BYTE>& key);
    ~AesGcm();

    std::vector<BYTE> encrypt(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& nonce);
    std::vector<BYTE> decrypt(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& nonce);

private:
#ifdef _WIN32
    void* algHandle_ = nullptr;
    void* keyHandle_ = nullptr;
#else
    EVP_CIPHER_CTX* ctx_ = nullptr;
    std::vector<BYTE> key_;
#endif
};

} // namespace crypto
