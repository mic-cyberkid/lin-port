#include "Screenshot.h"
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <jpeglib.h>

namespace capture {
    std::vector<uint8_t> CaptureScreenshotJPEG() {
        Display* display = XOpenDisplay(NULL);
        if (!display) return {};

        Window root = DefaultRootWindow(display);
        XWindowAttributes gwa;
        XGetWindowAttributes(display, root, &gwa);
        int width = gwa.width, height = gwa.height;

        XImage* image = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap);
        if (!image) { XCloseDisplay(display); return {}; }

        std::vector<uint8_t> jpegBuffer;
        struct jpeg_compress_struct cinfo;
        struct jpeg_error_mgr jerr;

        cinfo.err = jpeg_std_error(&jerr);
        jpeg_create_compress(&cinfo);

        unsigned char* outbuffer = NULL;
        unsigned long outsize = 0;
        jpeg_mem_dest(&cinfo, &outbuffer, &outsize);

        cinfo.image_width = width;
        cinfo.image_height = height;
        cinfo.input_components = 3;
        cinfo.in_color_space = JCS_RGB;

        jpeg_set_defaults(&cinfo);
        jpeg_set_quality(&cinfo, 75, TRUE);
        jpeg_start_compress(&cinfo, TRUE);

        std::vector<uint8_t> row(width * 3);
        while (cinfo.next_scanline < cinfo.image_height) {
            int y = cinfo.next_scanline;
            for (int x = 0; x < width; ++x) {
                unsigned long pixel = XGetPixel(image, x, y);
                row[x * 3 + 0] = (pixel >> 16) & 0xFF; // R
                row[x * 3 + 1] = (pixel >> 8) & 0xFF;  // G
                row[x * 3 + 2] = pixel & 0xFF;         // B
            }
            JSAMPROW row_pointer[1];
            row_pointer[0] = row.data();
            jpeg_write_scanlines(&cinfo, row_pointer, 1);
        }

        jpeg_finish_compress(&cinfo);

        if (outbuffer) {
            jpegBuffer.assign(outbuffer, outbuffer + outsize);
            free(outbuffer);
        }

        jpeg_destroy_compress(&cinfo);
        XDestroyImage(image);
        XCloseDisplay(display);
        return jpegBuffer;
    }
}
