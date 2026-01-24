#include <gtest/gtest.h>
#include "crypto/Base64.h"
#include <string>

TEST(Base64Test, EncodeDecode) {
    std::string original = "Hello, World!";
    std::vector<BYTE> data(original.begin(), original.end());
    std::string encoded = crypto::Base64Encode(data);
    std::vector<BYTE> decoded = crypto::Base64Decode(encoded);
    std::string decodedStr(decoded.begin(), decoded.end());
    EXPECT_EQ(original, decodedStr);
}

TEST(Base64Test, EmptyString) {
    std::string original = "";
    std::vector<BYTE> data(original.begin(), original.end());
    std::string encoded = crypto::Base64Encode(data);
    std::vector<BYTE> decoded = crypto::Base64Decode(encoded);
    EXPECT_TRUE(decoded.empty());
}

TEST(Base64Test, Padding) {
    std::vector<std::string> testStrings = {"a", "ab", "abc"};

    for (const auto& s : testStrings) {
        std::vector<BYTE> data(s.begin(), s.end());
        std::string encoded = crypto::Base64Encode(data);
        std::vector<BYTE> decoded = crypto::Base64Decode(encoded);
        std::string decodedStr(decoded.begin(), decoded.end());
        EXPECT_EQ(s, decodedStr);
    }
}
