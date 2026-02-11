#include "Base64.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstring>

namespace crypto {

    std::string Base64Encode(const std::vector<BYTE>& data) {
        if (data.empty()) return "";
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_write(bio, data.data(), (int)data.size());
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);

        std::string result(bufferPtr->data, bufferPtr->length);
        BIO_free_all(bio);
        return result;
    }

    std::vector<BYTE> Base64Decode(const std::string& data) {
        if (data.empty()) return {};
        BIO *bio, *b64;
        int decodeLen = (int)data.length() * 3 / 4 + 1;
        std::vector<BYTE> result(decodeLen);

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_new_mem_buf(data.data(), (int)data.length());
        bio = BIO_push(b64, bio);

        int actualLen = BIO_read(bio, result.data(), (int)data.length());
        if (actualLen < 0) actualLen = 0;
        result.resize(actualLen);
        BIO_free_all(bio);
        return result;
    }

}
