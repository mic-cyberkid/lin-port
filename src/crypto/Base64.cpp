#include "Base64.h"
#ifdef _WIN32
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#else
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstring>
#endif

namespace crypto {

    std::string Base64Encode(const std::vector<BYTE>& data) {
        if (data.empty()) return "";
#ifdef _WIN32
        DWORD len = 0;
        if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len)) return "";
        std::string result(len, '\0');
        if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &len)) return "";
        if (!result.empty() && result.back() == '\0') result.pop_back();
        return result;
#else
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_write(bio, data.data(), data.size());
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);

        std::string result(bufferPtr->data, bufferPtr->length);
        BIO_free_all(bio);
        return result;
#endif
    }

    std::vector<BYTE> Base64Decode(const std::string& data) {
        if (data.empty()) return {};
#ifdef _WIN32
        DWORD len = 0;
        if (!CryptStringToBinaryA(data.c_str(), (DWORD)data.length(), CRYPT_STRING_BASE64, NULL, &len, NULL, NULL)) return {};
        std::vector<BYTE> result(len);
        if (!CryptStringToBinaryA(data.c_str(), (DWORD)data.length(), CRYPT_STRING_BASE64, result.data(), &len, NULL, NULL)) return {};
        return result;
#else
        BIO *bio, *b64;
        int decodeLen = data.length() * 3 / 4;
        std::vector<BYTE> result(decodeLen);

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_new_mem_buf(data.data(), data.length());
        bio = BIO_push(b64, bio);

        int actualLen = BIO_read(bio, result.data(), data.length());
        result.resize(actualLen);
        BIO_free_all(bio);
        return result;
#endif
    }

}
