#include "Exec.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <cstdio>
#include <memory>
#include <array>
#endif
namespace utils {
    std::string RunCommand(const std::string& cmd) {
#ifdef _WIN32
        std::string res; HANDLE hR, hW; SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
        if (!CreatePipe(&hR, &hW, &sa, 0)) return "";
        SetHandleInformation(hR, HANDLE_FLAG_INHERIT, 0);
        STARTUPINFOA si = {sizeof(si)}; PROCESS_INFORMATION pi;
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; si.hStdOutput = hW; si.hStdError = hW; si.wShowWindow = SW_HIDE;
        if (!CreateProcessA(NULL, (char*)("cmd.exe /c " + cmd).c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) { CloseHandle(hR); CloseHandle(hW); return ""; }
        CloseHandle(hW); char buf[4096]; DWORD n;
        while (ReadFile(hR, buf, 4096, &n, NULL) && n > 0) res.append(buf, n);
        CloseHandle(hR); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return res;
#else
        std::array<char, 128> buf; std::string res;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
        if (!pipe) return "";
        while (fgets(buf.data(), buf.size(), pipe.get()) != nullptr) res += buf.data();
        return res;
#endif
    }
}
