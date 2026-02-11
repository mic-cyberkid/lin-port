#pragma once

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <cstdint>

typedef uint8_t BYTE;

namespace crypto {

class AesGcm {
public:
    AesGcm(const std::vector<BYTE>& key);
    ~AesGcm();

    std::vector<BYTE> encrypt(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& nonce);
    std::vector<BYTE> decrypt(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& nonce);

private:
    EVP_CIPHER_CTX* ctx_ = nullptr;
    std::vector<BYTE> key_;
};

} // namespace crypto
