#include "AesGcm.h"
#include <stdexcept>

namespace crypto {

AesGcm::AesGcm(const std::vector<BYTE>& key) : key_(key) {
    ctx_ = EVP_CIPHER_CTX_new();
    if (!ctx_) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
}

AesGcm::~AesGcm() {
    if (ctx_) EVP_CIPHER_CTX_free(ctx_);
}

std::vector<BYTE> AesGcm::encrypt(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& nonce) {
    int len;
    int ciphertextLen;
    std::vector<BYTE> ciphertext(plaintext.size());
    std::vector<BYTE> tag(16);
    if (1 != EVP_EncryptInit_ex(ctx_, EVP_aes_256_gcm(), NULL, NULL, NULL)) throw std::runtime_error("EVP_EncryptInit_ex failed");
    if (1 != EVP_EncryptInit_ex(ctx_, NULL, NULL, key_.data(), nonce.data())) throw std::runtime_error("EVP_EncryptInit_ex failed");
    if (1 != EVP_EncryptUpdate(ctx_, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size())) throw std::runtime_error("EVP_EncryptUpdate failed");
    ciphertextLen = len;
    if (1 != EVP_EncryptFinal_ex(ctx_, ciphertext.data() + len, &len)) throw std::runtime_error("EVP_EncryptFinal_ex failed");
    ciphertextLen += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) throw std::runtime_error("Failed to get tag");
    ciphertext.resize(ciphertextLen);
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}

std::vector<BYTE> AesGcm::decrypt(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& nonce) {
    if (ciphertext.size() < 16) throw std::runtime_error("Ciphertext too short");
    int len;
    int plaintextLen;
    std::vector<BYTE> plaintext(ciphertext.size() - 16);
    std::vector<BYTE> encryptedData(ciphertext.begin(), ciphertext.end() - 16);
    std::vector<BYTE> tag(ciphertext.end() - 16, ciphertext.end());
    if (1 != EVP_DecryptInit_ex(ctx_, EVP_aes_256_gcm(), NULL, NULL, NULL)) throw std::runtime_error("EVP_DecryptInit_ex failed");
    if (1 != EVP_DecryptInit_ex(ctx_, NULL, NULL, key_.data(), nonce.data())) throw std::runtime_error("EVP_DecryptInit_ex failed");
    if (1 != EVP_DecryptUpdate(ctx_, plaintext.data(), &len, encryptedData.data(), (int)encryptedData.size())) throw std::runtime_error("EVP_DecryptUpdate failed");
    plaintextLen = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, 16, tag.data())) throw std::runtime_error("Failed to set tag");
    int ret = EVP_DecryptFinal_ex(ctx_, plaintext.data() + len, &len);
    if (ret > 0) {
        plaintextLen += len;
        plaintext.resize(plaintextLen);
        return plaintext;
    } else throw std::runtime_error("Decryption/Authentication failed");
}

} // namespace crypto
