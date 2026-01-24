// src/decoy/Decoy.cpp
#include "Decoy.h"
#include <windows.h>
#include <wingdi.h>
#include "../utils/Logger.h"

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

namespace decoy {

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_KEYDOWN: {
            if (wParam == 'B' && GetAsyncKeyState(VK_CONTROL)) {
                // Ctrl + B → exit the fake BSOD
                DestroyWindow(hwnd);
                return 0;
            }
            return 0; // swallow all other keys
        }
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            RECT rect;
            GetClientRect(hwnd, &rect);

            // Background — classic BSOD blue
            HBRUSH bgBrush = CreateSolidBrush(RGB(0, 51, 160)); // #0033A0-ish
            FillRect(hdc, &rect, bgBrush);
            DeleteObject(bgBrush);

            // ────────────────────────────────────────────────────────────────
            // Main sad face emoji (Unicode + large font)
            // ────────────────────────────────────────────────────────────────
            HFONT hFontSad = CreateFontW(
                -MulDiv(140, GetDeviceCaps(hdc, LOGPIXELSY), 72),  // ~140pt
                0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI Emoji"
            );
            SelectObject(hdc, hFontSad);

            SetTextColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, TRANSPARENT);

            TextOutW(hdc, rect.right / 2 - 80, 120, L":-(", 3);

            DeleteObject(hFontSad);

            // ────────────────────────────────────────────────────────────────
            // Main title text
            // ─────────────────────────────────────────────────────────────────
            HFONT hFontTitle = CreateFontW(
                -MulDiv(48, GetDeviceCaps(hdc, LOGPIXELSY), 72),
                0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI"
            );
            SelectObject(hdc, hFontTitle);

            const wchar_t* title = L"Your device ran into a problem and needs to restart.";
            TextOutW(hdc, 80, 240, title, (int)wcslen(title));

            DeleteObject(hFontTitle);

            // ────────────────────────────────────────────────────────────────
            // Details block (smaller text)
            // ─────────────────────────────────────────────────────────────────
            HFONT hFontDetail = CreateFontW(
                -MulDiv(24, GetDeviceCaps(hdc, LOGPIXELSY), 72),
                0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI"
            );
            SelectObject(hdc, hFontDetail);

            int y = 340;
            const wchar_t* lines[] = {
                L"We're just collecting some error info, and then we'll restart for you.",
                L"(0% complete)",
                L"",
                L"If you'd like to know more, you can search online for this error: ",
                L"CRITICAL_PROCESS_DIED",
                L"",
                L"Stop code:          CRITICAL_PROCESS_DIED",
                L"What failed:        services.exe",
                L"",
                L"More info: https://aka.ms/stopcode"
            };

            for (const auto& line : lines) {
                TextOutW(hdc, 80, y, line, (int)wcslen(line));
                y += 40;
            }

            DeleteObject(hFontDetail);

            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void ShowFakeBSOD() {
    LOG_INFO("Displaying fake BSOD decoy (exit with Ctrl+B)");

    // Register window class
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.lpszClassName = L"FakeBSODClass";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);

    RegisterClassExW(&wc);

    // Create full-screen window
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_APPWINDOW,
        L"FakeBSODClass",
        L"Windows Problem",
        WS_POPUP | WS_VISIBLE,
        0, 0, screenW, screenH,
        NULL, NULL, wc.hInstance, NULL
    );

    if (!hwnd) return;

    // Hide cursor & steal focus
    ShowCursor(FALSE);
    SetForegroundWindow(hwnd);

    // Message loop — blocks until Ctrl+B
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    ShowCursor(TRUE);
    UnregisterClassW(L"FakeBSODClass", wc.hInstance);
}

void ShowInfoMessage() {
    // Old boring version is replaced — now we show fake BSOD instead
    ShowFakeBSOD();
}

} // namespace decoy
