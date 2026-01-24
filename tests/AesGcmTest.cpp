#include <gtest/gtest.h>
#include "crypto/AesGcm.h"
#include <vector>
#include <string>

TEST(AesGcmTest, EncryptDecrypt) {
    std::vector<uint8_t> key(32, 0x41); // 256-bit key
    std::vector<uint8_t> nonce(12, 0x42);
    std::string plaintextStr = "Secret message";
    std::vector<uint8_t> plaintext(plaintextStr.begin(), plaintextStr.end());
    
    crypto::AesGcm encryptor(key);
    std::vector<uint8_t> ciphertext = encryptor.encrypt(plaintext, nonce);
    
    EXPECT_FALSE(ciphertext.empty());
    EXPECT_NE(plaintext, ciphertext);

    std::vector<uint8_t> decrypted = encryptor.decrypt(ciphertext, nonce);
    std::string decryptedStr(decrypted.begin(), decrypted.end());
    EXPECT_EQ(plaintextStr, decryptedStr);
}

TEST(AesGcmTest, WrongKeyFails) {
    std::vector<uint8_t> key1(32, 0x41);
    std::vector<uint8_t> key2(32, 0x42);
    std::vector<uint8_t> nonce(12, 0x43);
    std::string plaintextStr = "Secret message";
    std::vector<uint8_t> plaintext(plaintextStr.begin(), plaintextStr.end());
    
    crypto::AesGcm encryptor1(key1);
    std::vector<uint8_t> ciphertext = encryptor1.encrypt(plaintext, nonce);
    
    crypto::AesGcm encryptor2(key2);
    EXPECT_THROW(encryptor2.decrypt(ciphertext, nonce), std::exception);
}
