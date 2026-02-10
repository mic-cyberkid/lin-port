#include "AesGcm.h"
#include <stdexcept>

namespace crypto {

#ifdef _WIN32
AesGcm::AesGcm(const std::vector<BYTE>& key) {
    NTSTATUS status;
    status = BCryptOpenAlgorithmProvider((BCRYPT_ALG_HANDLE*)&algHandle_, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Failed to open AES algorithm provider.");
    status = BCryptSetProperty((BCRYPT_ALG_HANDLE)algHandle_, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)algHandle_, 0);
        throw std::runtime_error("Failed to set GCM chaining mode.");
    }
    status = BCryptGenerateSymmetricKey((BCRYPT_ALG_HANDLE)algHandle_, (BCRYPT_KEY_HANDLE*)&keyHandle_, NULL, 0, (PBYTE)key.data(), static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)algHandle_, 0);
        throw std::runtime_error("Failed to generate symmetric key.");
    }
}

AesGcm::~AesGcm() {
    if (keyHandle_) BCryptDestroyKey((BCRYPT_KEY_HANDLE)keyHandle_);
    if (algHandle_) BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)algHandle_, 0);
}

std::vector<BYTE> AesGcm::encrypt(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& nonce) {
    NTSTATUS status;
    DWORD ciphertextLen = 0;
    std::vector<BYTE> tag(16);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PBYTE)nonce.data();
    authInfo.cbNonce = static_cast<ULONG>(nonce.size());
    authInfo.pbTag = tag.data();
    authInfo.cbTag = static_cast<ULONG>(tag.size());

    status = BCryptEncrypt((BCRYPT_KEY_HANDLE)keyHandle_, (PBYTE)plaintext.data(), static_cast<ULONG>(plaintext.size()), &authInfo, NULL, 0, NULL, 0, &ciphertextLen, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Failed to get encrypted buffer size.");
    std::vector<BYTE> ciphertext(ciphertextLen);
    status = BCryptEncrypt((BCRYPT_KEY_HANDLE)keyHandle_, (PBYTE)plaintext.data(), static_cast<ULONG>(plaintext.size()), &authInfo, NULL, 0, ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &ciphertextLen, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Encryption failed.");
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}

std::vector<BYTE> AesGcm::decrypt(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& nonce) {
    if (ciphertext.size() < 16) throw std::runtime_error("Invalid ciphertext.");
    NTSTATUS status;
    DWORD plaintextLen = 0;
    std::vector<BYTE> encryptedData(ciphertext.begin(), ciphertext.end() - 16);
    std::vector<BYTE> tag(ciphertext.end() - 16, ciphertext.end());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PBYTE)nonce.data();
    authInfo.cbNonce = static_cast<ULONG>(nonce.size());
    authInfo.pbTag = tag.data();
    authInfo.cbTag = static_cast<ULONG>(tag.size());

    status = BCryptDecrypt((BCRYPT_KEY_HANDLE)keyHandle_, (PBYTE)encryptedData.data(), static_cast<ULONG>(encryptedData.size()), &authInfo, NULL, 0, NULL, 0, &plaintextLen, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Failed to get decrypted buffer size.");
    std::vector<BYTE> plaintext(plaintextLen);
    status = BCryptDecrypt((BCRYPT_KEY_HANDLE)keyHandle_, (PBYTE)encryptedData.data(), static_cast<ULONG>(encryptedData.size()), &authInfo, NULL, 0, plaintext.data(), static_cast<ULONG>(plaintext.size()), &plaintextLen, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Decryption failed.");
    return plaintext;
}
#else
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
    if (1 != EVP_EncryptUpdate(ctx_, ciphertext.data(), &len, plaintext.data(), plaintext.size())) throw std::runtime_error("EVP_EncryptUpdate failed");
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
    if (1 != EVP_DecryptUpdate(ctx_, plaintext.data(), &len, encryptedData.data(), encryptedData.size())) throw std::runtime_error("EVP_DecryptUpdate failed");
    plaintextLen = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, 16, tag.data())) throw std::runtime_error("Failed to set tag");
    int ret = EVP_DecryptFinal_ex(ctx_, plaintext.data() + len, &len);
    if (ret > 0) {
        plaintextLen += len;
        plaintext.resize(plaintextLen);
        return plaintext;
    } else throw std::runtime_error("Decryption/Authentication failed");
}
#endif

} // namespace crypto
