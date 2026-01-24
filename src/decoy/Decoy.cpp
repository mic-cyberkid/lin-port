#include "Decoy.h"
#include <windows.h>
#include "../utils/Logger.h"

namespace decoy {

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

void ShowBSOD() {
    HINSTANCE hInstance = GetModuleHandle(NULL);
    const wchar_t CLASS_NAME[] = L"BSODWindowClass";

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClassW(&wc);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        CLASS_NAME,
        L"BSOD",
        WS_POPUP,
        0, 0, screenWidth, screenHeight,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) {
        return;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_CREATE:
            SetTimer(hwnd, 1, 150, NULL); // Timer for percentage update
            return 0;

        case WM_TIMER:
            {
                static int percentage = 0;
                percentage = (percentage + 7) % 100;
                InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            RECT clientRect;
            GetClientRect(hwnd, &clientRect);

            // Background
            HBRUSH hBrush = CreateSolidBrush(RGB(10, 85, 155));
            FillRect(hdc, &clientRect, hBrush);
            DeleteObject(hBrush);

            // Text
            SetTextColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, TRANSPARENT);

            HFONT hFont = CreateFontW(120, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_MODERN, L"Segoe UI");
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);

            TextOutW(hdc, 150, 150, L":(", 2);

            SelectObject(hdc, CreateFontW(36, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_MODERN, L"Segoe UI"));
            TextOutW(hdc, 150, 350, L"Your PC ran into a problem and needs to restart. We're just", 63);
            TextOutW(hdc, 150, 400, L"collecting some error info, and then we'll restart for you.", 63);

            static int percentage = 0;
            percentage = (percentage + 7) % 100;
            std::wstring percentageText = std::to_wstring(percentage) + L"% complete";
            TextOutW(hdc, 150, 500, percentageText.c_str(), (int)percentageText.length());

            SelectObject(hdc, CreateFontW(22, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_MODERN, L"Consolas"));
            TextOutW(hdc, 150, 650, L"For more information about this issue and possible fixes, visit", 63);
            TextOutW(hdc, 150, 680, L"https://www.windows.com/stopcode", 32);
            TextOutW(hdc, 150, 750, L"If you call a support person, give them this info:", 50);
            TextOutW(hdc, 150, 780, L"Stop code: CRITICAL_PROCESS_DIED", 32);


            SelectObject(hdc, hOldFont);
            DeleteObject(hFont);

            EndPaint(hwnd, &ps);
        }
        return 0;

        case WM_KEYDOWN:
            if (wParam == 'B' && GetKeyState(VK_CONTROL) < 0) {
                DestroyWindow(hwnd);
            }
            return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

} // namespace decoy
