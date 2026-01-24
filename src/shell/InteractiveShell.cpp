#include "InteractiveShell.h"
#include <windows.h>
#include <thread>
#include <vector>
#include <mutex>

namespace shell {

    namespace {
        HANDLE hChildStd_IN_Rd = NULL;
        HANDLE hChildStd_IN_Wr = NULL;
        HANDLE hChildStd_OUT_Rd = NULL;
        HANDLE hChildStd_OUT_Wr = NULL;
        
        HANDLE hProcess = NULL;
        std::thread readerThread;
        bool isRunning = false;
        std::mutex shellMutex;

        void ReadOutputLoop(ShellCallback callback) {
            DWORD dwRead;
            CHAR chBuf[4096];
            BOOL bSuccess = FALSE;

            while (isRunning) {
                bSuccess = ReadFile(hChildStd_OUT_Rd, chBuf, 4096, &dwRead, NULL);
                if (!bSuccess || dwRead == 0) break;

                std::string output(chBuf, dwRead);
                callback(output);
            }
        }
    }

    void StartShell(ShellCallback callback) {
        std::lock_guard<std::mutex> lock(shellMutex);
        if (isRunning) return;

        SECURITY_ATTRIBUTES saAttr;
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0)) return;
        if (!SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) return;

        if (!CreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &saAttr, 0)) return;
        if (!SetHandleInformation(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) return;

        PROCESS_INFORMATION piProcInfo;
        STARTUPINFOA siStartInfo;
        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
        ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
        siStartInfo.cb = sizeof(STARTUPINFO);
        siStartInfo.hStdError = hChildStd_OUT_Wr;
        siStartInfo.hStdOutput = hChildStd_OUT_Wr;
        siStartInfo.hStdInput = hChildStd_IN_Rd;
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        siStartInfo.wShowWindow = SW_HIDE;

        char cmdLine[] = "cmd.exe";
        BOOL bSuccess = CreateProcessA(NULL,
            cmdLine,
            NULL,
            NULL,
            TRUE,
            0,
            NULL,
            NULL,
            &siStartInfo,
            &piProcInfo);
        
        if (bSuccess) {
             hProcess = piProcInfo.hProcess;
             CloseHandle(piProcInfo.hThread);
             CloseHandle(hChildStd_OUT_Wr); // Close write end of output pipe in this process
             CloseHandle(hChildStd_IN_Rd); // Close read end of input pipe in this process
             
             isRunning = true;
             readerThread = std::thread(ReadOutputLoop, callback);
             readerThread.detach();
        } else {
             // Cleanup if failed
             CloseHandle(hChildStd_OUT_Wr);
             CloseHandle(hChildStd_OUT_Rd);
             CloseHandle(hChildStd_IN_Wr);
             CloseHandle(hChildStd_IN_Rd);
        }
    }

    void StopShell() {
        std::lock_guard<std::mutex> lock(shellMutex);
        if (!isRunning) return;
        isRunning = false;
        
        // Terminate process
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
            hProcess = NULL;
        }

        // Close pipes
        if (hChildStd_IN_Wr) { CloseHandle(hChildStd_IN_Wr); hChildStd_IN_Wr = NULL; }
        if (hChildStd_OUT_Rd) { CloseHandle(hChildStd_OUT_Rd); hChildStd_OUT_Rd = NULL; }
    }

    void WriteToShell(const std::string& cmd) {
        std::lock_guard<std::mutex> lock(shellMutex);
        if (!isRunning || !hChildStd_IN_Wr) return;

        DWORD dwWritten;
        std::string cmdWithNewline = cmd + "\n";
        WriteFile(hChildStd_IN_Wr, cmdWithNewline.c_str(), (DWORD)cmdWithNewline.length(), &dwWritten, NULL);
    }

    bool IsShellRunning() {
        return isRunning;
    }

}
