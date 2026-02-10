#include "Screenshot.h"
#ifdef _WIN32
#include <gdiplus.h>
#include <memory>
#pragma comment(lib, "gdiplus.lib")
namespace capture {
    std::vector<BYTE> CaptureScreenshotJPEG() { return {}; }
}
#else
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <vector>
#include <cstdint>
namespace capture {
    std::vector<uint8_t> CaptureScreenshotJPEG() {
        Display* display = XOpenDisplay(NULL); if (!display) return {};
        Window root = DefaultRootWindow(display); XWindowAttributes gwa; XGetWindowAttributes(display, root, &gwa);
        int width = gwa.width, height = gwa.height;
        XImage* image = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap); if (!image) { XCloseDisplay(display); return {}; }
        std::vector<uint8_t> bmp; uint32_t rowSize = (width * 3 + 3) & ~3; uint32_t fileSize = 54 + rowSize * height;
        bmp.push_back('B'); bmp.push_back('M'); bmp.push_back(fileSize & 0xFF); bmp.push_back((fileSize >> 8) & 0xFF);
        bmp.push_back((fileSize >> 16) & 0xFF); bmp.push_back((fileSize >> 24) & 0xFF);
        bmp.push_back(0); bmp.push_back(0); bmp.push_back(0); bmp.push_back(0);
        bmp.push_back(54); bmp.push_back(0); bmp.push_back(0); bmp.push_back(0);
        bmp.push_back(40); bmp.push_back(0); bmp.push_back(0); bmp.push_back(0);
        bmp.push_back(width & 0xFF); bmp.push_back((width >> 8) & 0xFF); bmp.push_back((width >> 16) & 0xFF); bmp.push_back((width >> 24) & 0xFF);
        bmp.push_back(height & 0xFF); bmp.push_back((height >> 8) & 0xFF); bmp.push_back((height >> 16) & 0xFF); bmp.push_back((height >> 24) & 0xFF);
        bmp.push_back(1); bmp.push_back(0); bmp.push_back(24); bmp.push_back(0);
        for (int i = 0; i < 24; ++i) bmp.push_back(0);
        for (int y = height - 1; y >= 0; --y) {
            for (int x = 0; x < width; ++x) {
                unsigned long pixel = XGetPixel(image, x, y);
                bmp.push_back(pixel & 0xFF); bmp.push_back((pixel >> 8) & 0xFF); bmp.push_back((pixel >> 16) & 0xFF);
            }
            for (int p = 0; p < (int)(rowSize - width * 3); ++p) bmp.push_back(0);
        }
        XDestroyImage(image); XCloseDisplay(display); return bmp;
    }
}
#endif
