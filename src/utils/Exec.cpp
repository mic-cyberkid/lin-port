#include "Exec.h"
#include <windows.h>
#include <vector>
#include <iostream>

namespace utils {

    std::string RunCommand(const std::string& cmd) {
        std::string result;
        HANDLE hPipeRead, hPipeWrite;

        SECURITY_ATTRIBUTES saAttr;
        RtlZeroMemory(&saAttr, sizeof(saAttr));
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.lpSecurityDescriptor = NULL;
        saAttr.bInheritHandle = TRUE;

        if (!CreatePipe(&hPipeRead, &hPipeWrite, &saAttr, 0)) {
            return "";
        }

        // Ensure the read handle to the pipe for STDOUT is not inherited.
        SetHandleInformation(hPipeRead, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        RtlZeroMemory(&si, sizeof(si));
        RtlZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = hPipeWrite;
        si.hStdError = hPipeWrite;
        si.wShowWindow = SW_HIDE; // Hide window

        std::string cmdLine = "cmd.exe /c " + cmd;

        if (!CreateProcessA(NULL, &cmdLine[0], NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            CloseHandle(hPipeWrite);
            CloseHandle(hPipeRead);
            return "";
        }

        // Close the write end of the pipe before reading from the read end of the pipe,
        // to enable multiple processes using the pipe.
        CloseHandle(hPipeWrite);

        DWORD dwRead;
        CHAR chBuf[4096];
        BOOL bSuccess = FALSE;

        for (;;) {
            bSuccess = ReadFile(hPipeRead, chBuf, 4096, &dwRead, NULL);
            if (!bSuccess || dwRead == 0) break;
            result.append(chBuf, dwRead);
        }

        CloseHandle(hPipeRead);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return result;
    }

}
