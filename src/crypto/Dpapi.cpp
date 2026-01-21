#include "crypto/Dpapi.h"
#include <wincrypt.h>

namespace crypto {

std::vector<BYTE> decryptDpapi(const std::vector<BYTE>& data) {
    if (data.empty()) {
        return {};
    }

    DATA_BLOB in{};
    DATA_BLOB out{};

    in.pbData = const_cast<BYTE*>(data.data());
    in.cbData = static_cast<DWORD>(data.size());

    if (!CryptUnprotectData(
            &in,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            0,
            &out)) {
        return {};
    }

    std::vector<BYTE> result(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return result;
}

} // namespace crypto
