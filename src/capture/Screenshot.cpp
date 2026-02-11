#include "Screenshot.h"
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <jpeglib.h>

namespace capture {

    typedef struct jpeg_error_mgr* (*jpeg_std_error_t)(struct jpeg_error_mgr*);
    typedef void (*jpeg_CreateCompress_t)(j_compress_ptr, int, size_t);
    typedef void (*jpeg_mem_dest_t)(j_compress_ptr, unsigned char**, unsigned long*);
    typedef void (*jpeg_set_defaults_t)(j_compress_ptr);
    typedef void (*jpeg_set_quality_t)(j_compress_ptr, int, boolean);
    typedef void (*jpeg_start_compress_t)(j_compress_ptr, boolean);
    typedef JDIMENSION (*jpeg_write_scanlines_t)(j_compress_ptr, JSAMPARRAY, JDIMENSION);
    typedef void (*jpeg_finish_compress_t)(j_compress_ptr);
    typedef void (*jpeg_destroy_compress_t)(j_compress_ptr);

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

        void* handle = dlopen("libjpeg.so.62", RTLD_LAZY);
        if (!handle) handle = dlopen("libjpeg.so.8", RTLD_LAZY);
        if (!handle) handle = dlopen("libjpeg.so", RTLD_LAZY);

        if (!handle) {
            // Fallback to BMP if jpeg is not available
            XDestroyImage(image);
            XCloseDisplay(display);
            return {}; // Or implement BMP fallback here
        }

        auto fn_std_error = (jpeg_std_error_t)dlsym(handle, "jpeg_std_error");
        auto fn_CreateCompress = (jpeg_CreateCompress_t)dlsym(handle, "jpeg_CreateCompress");
        auto fn_mem_dest = (jpeg_mem_dest_t)dlsym(handle, "jpeg_mem_dest");
        auto fn_set_defaults = (jpeg_set_defaults_t)dlsym(handle, "jpeg_set_defaults");
        auto fn_set_quality = (jpeg_set_quality_t)dlsym(handle, "jpeg_set_quality");
        auto fn_start_compress = (jpeg_start_compress_t)dlsym(handle, "jpeg_start_compress");
        auto fn_write_scanlines = (jpeg_write_scanlines_t)dlsym(handle, "jpeg_write_scanlines");
        auto fn_finish_compress = (jpeg_finish_compress_t)dlsym(handle, "jpeg_finish_compress");
        auto fn_destroy_compress = (jpeg_destroy_compress_t)dlsym(handle, "jpeg_destroy_compress");

        if (!fn_std_error || !fn_CreateCompress || !fn_mem_dest || !fn_set_defaults ||
            !fn_set_quality || !fn_start_compress || !fn_write_scanlines ||
            !fn_finish_compress || !fn_destroy_compress) {
            dlclose(handle);
            XDestroyImage(image);
            XCloseDisplay(display);
            return {};
        }

        struct jpeg_compress_struct cinfo;
        struct jpeg_error_mgr jerr;

        cinfo.err = fn_std_error(&jerr);
        fn_CreateCompress(&cinfo, JPEG_LIB_VERSION, sizeof(struct jpeg_compress_struct));

        unsigned char* outbuffer = NULL;
        unsigned long outsize = 0;
        fn_mem_dest(&cinfo, &outbuffer, &outsize);

        cinfo.image_width = width;
        cinfo.image_height = height;
        cinfo.input_components = 3;
        cinfo.in_color_space = JCS_RGB;

        fn_set_defaults(&cinfo);
        fn_set_quality(&cinfo, 75, TRUE);
        fn_start_compress(&cinfo, TRUE);

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
            fn_write_scanlines(&cinfo, row_pointer, 1);
        }

        fn_finish_compress(&cinfo);

        if (outbuffer) {
            jpegBuffer.assign(outbuffer, outbuffer + outsize);
            free(outbuffer);
        }

        fn_destroy_compress(&cinfo);
        dlclose(handle);
        XDestroyImage(image);
        XCloseDisplay(display);
        return jpegBuffer;
    }
}
