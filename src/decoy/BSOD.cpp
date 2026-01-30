#include "BSOD.h"
#include "../utils/Logger.h"
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>

namespace decoy {

namespace {
    std::atomic<int> g_progress(0);

    LRESULT CALLBACK BSODWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
        switch (message) {
            case WM_PAINT: {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hWnd, &ps);

                // Blue background
                HBRUSH hBrush = CreateSolidBrush(RGB(0, 120, 215));
                FillRect(hdc, &ps.rcPaint, hBrush);
                DeleteObject(hBrush);

                // White text
                SetTextColor(hdc, RGB(255, 255, 255));
                SetBkMode(hdc, TRANSPARENT);

                HFONT hFont = CreateFontA(80, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
                    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
                HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);

                RECT rc;
                GetClientRect(hWnd, &rc);

                RECT rcText = rc;
                rcText.left += 100;
                rcText.top += 150;

                TextOutA(hdc, rcText.left, rcText.top, ":(", 2);

                HFONT hFontSmall = CreateFontA(30, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
                    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
                SelectObject(hdc, hFontSmall);

                rcText.top += 120;
                std::string msg = "Your PC ran into a problem and needs to restart. We're just\ncollecting some error info, and then we'll restart for you.";
                DrawTextA(hdc, msg.c_str(), -1, &rcText, DT_LEFT | DT_WORDBREAK);

                rcText.top += 150;
                std::string info = std::to_string(g_progress.load()) + "% complete";
                TextOutA(hdc, rcText.left, rcText.top, info.c_str(), (int)info.length());

                rcText.top += 200;
                std::string stopCode = "For more information about this issue and possible fixes, visit https://www.windows.com/stopcode\n\nIf you call a support person, give them this info:\nStop code: CRITICAL_PROCESS_DIED";
                DrawTextA(hdc, stopCode.c_str(), -1, &rcText, DT_LEFT | DT_WORDBREAK);

                SelectObject(hdc, hOldFont);
                DeleteObject(hFont);
                DeleteObject(hFontSmall);

                EndPaint(hWnd, &ps);
                break;
            }
            case WM_KEYDOWN: {
                // Check for CTRL+B
                if (wParam == 'B' && (GetKeyState(VK_CONTROL) & 0x8000)) {
                    LOG_INFO("Decoy exit sequence triggered.");
                    DestroyWindow(hWnd);
                }
                break;
            }
            case WM_TIMER: {
                if (g_progress.load() < 100) {
                    g_progress += (rand() % 5);
                    if (g_progress > 100) g_progress = 100;
                    InvalidateRect(hWnd, NULL, TRUE);
                }
                // Aggressively re-assert top-most every timer tick
                SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                break;
            }
            case WM_DESTROY:
                PostQuitMessage(0);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
        }
        return 0;
    }
}

void ShowBSOD() {
    LOG_INFO("Displaying BSOD decoy...");

    // Give time for any previous windows to settle
    Sleep(1000);

    HINSTANCE hInstance = GetModuleHandle(NULL);
    WNDCLASSEXA wc;
    RtlZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = BSODWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "WindowsBSODDecoy";
    wc.hCursor = NULL; // No cursor for the window class

    RegisterClassExA(&wc);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    LOG_DEBUG("Screen dimensions detected: " + std::to_string(screenWidth) + "x" + std::to_string(screenHeight));

    HWND hWnd = CreateWindowExA(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, wc.lpszClassName, "BSOD", WS_POPUP | WS_VISIBLE,
        0, 0, screenWidth, screenHeight, NULL, NULL, hInstance, NULL);

    if (hWnd) {
        LOG_INFO("Decoy window created successfully. Handle: 0x" + std::to_string((uintptr_t)hWnd));

        // Force the window to the front
        DWORD foreThread = GetWindowThreadProcessId(GetForegroundWindow(), NULL);
        DWORD appThread = GetCurrentThreadId();
        if (foreThread != appThread) {
            AttachThreadInput(foreThread, appThread, TRUE);
            SetForegroundWindow(hWnd);
            SetFocus(hWnd);
            SetActiveWindow(hWnd);
            AttachThreadInput(foreThread, appThread, FALSE);
        } else {
            SetForegroundWindow(hWnd);
            SetFocus(hWnd);
            SetActiveWindow(hWnd);
        }

        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, screenWidth, screenHeight, SWP_SHOWWINDOW);
        UpdateWindow(hWnd);

        // Hide the cursor
        ShowCursor(FALSE);

        // Set a timer to update progress and re-assert topmost
        SetTimer(hWnd, 1, 1000, NULL);

        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        ShowCursor(TRUE);
    } else {
        LOG_ERR("Failed to create decoy window: " + std::to_string(GetLastError()));
    }
}

} // namespace decoy
