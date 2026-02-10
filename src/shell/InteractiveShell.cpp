#include "InteractiveShell.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <pty.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#endif
#include <thread>
#include <vector>
#include <mutex>
#include <cstring>
namespace shell {
    namespace {
#ifdef _WIN32
        HANDLE hChildStd_IN_Wr = NULL;
        HANDLE hChildStd_OUT_Rd = NULL;
        HANDLE hProcess = NULL;
#else
        int masterFd = -1;
        pid_t childPid = -1;
#endif
        std::thread readerThread;
        bool isRunning = false;
        std::mutex shellMutex;
        void ReadOutputLoop(ShellCallback callback) {
            char buf[4096];
            while (isRunning) {
#ifdef _WIN32
                DWORD dwRead; if (!ReadFile(hChildStd_OUT_Rd, buf, sizeof(buf), &dwRead, NULL) || dwRead == 0) break;
                std::string output(buf, dwRead);
#else
                ssize_t n = read(masterFd, buf, sizeof(buf)); if (n <= 0) break;
                std::string output(buf, n);
#endif
                callback(output);
            }
            isRunning = false;
        }
    }
    void StartShell(ShellCallback callback) {
        std::lock_guard<std::mutex> lock(shellMutex); if (isRunning) return;
#ifdef _WIN32
        // Windows implementation
#else
        childPid = forkpty(&masterFd, NULL, NULL, NULL);
        if (childPid == 0) { execl("/bin/sh", "sh", "-i", NULL); _exit(1); }
        else if (childPid > 0) { isRunning = true; readerThread = std::thread(ReadOutputLoop, callback); readerThread.detach(); }
#endif
    }
    void StopShell() {
        std::lock_guard<std::mutex> lock(shellMutex); if (!isRunning) return; isRunning = false;
#ifdef _WIN32
        // Windows cleanup
#else
        if (childPid > 0) { kill(childPid, SIGTERM); waitpid(childPid, NULL, WNOHANG); childPid = -1; }
        if (masterFd != -1) { close(masterFd); masterFd = -1; }
#endif
    }
    void WriteToShell(const std::string& cmd) {
        std::lock_guard<std::mutex> lock(shellMutex); if (!isRunning) return;
        std::string c = cmd + "\n";
#ifdef _WIN32
        DWORD dw; WriteFile(hChildStd_IN_Wr, c.c_str(), (DWORD)c.length(), &dw, NULL);
#else
        write(masterFd, c.c_str(), c.length());
#endif
    }
    bool IsShellRunning() { return isRunning; }
}
