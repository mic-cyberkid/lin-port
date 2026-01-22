#include "Screenshot.h"
#include <gdiplus.h>
#include <memory>
#include <iostream>

#pragma comment(lib, "gdiplus.lib")

namespace capture {

    using namespace Gdiplus;

    int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT  num = 0;          // number of image encoders
        UINT  size = 0;         // size of the image encoder array in bytes

        GetImageEncodersSize(&num, &size);
        if (size == 0) return -1;  // Failure

        std::unique_ptr<ImageCodecInfo[]> pImageCodecInfo(reinterpret_cast<ImageCodecInfo*>(new BYTE[size]));
        if (pImageCodecInfo == nullptr) return -1;  // Failure

        GetImageEncoders(num, size, pImageCodecInfo.get());

        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[j].Clsid;
                return j;  // Success
            }
        }
        return -1;  // Failure
    }

    std::vector<BYTE> CaptureScreenshotJPEG() {
        std::vector<BYTE> buffer;

        // Initialize GDI+
        GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        if (GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Ok) {
            return buffer;
        }

        { // Scoping for GDI+ objects before shutdown
            HDC hdcScreen = GetDC(NULL);
            HDC hdcMemDC = CreateCompatibleDC(hdcScreen);
            
            int width = GetSystemMetrics(SM_CXSCREEN);
            int height = GetSystemMetrics(SM_CYSCREEN);

            HBITMAP hbmScreen = CreateCompatibleBitmap(hdcScreen, width, height);
            SelectObject(hdcMemDC, hbmScreen);

            // Copy screen to memory DC
            if (BitBlt(hdcMemDC, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY)) {
                
                Bitmap bitmap(hbmScreen, NULL);
                CLSID encoderClsid;
                if (GetEncoderClsid(L"image/jpeg", &encoderClsid) != -1) {
                    
                    // Save to IStream (Memory)
                    IStream* pStream = NULL;
                    if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
                        
                        // Set Quality (optional, default is usually okay ~75)
                        EncoderParameters encoderParameters;
                        encoderParameters.Count = 1;
                        encoderParameters.Parameter[0].Guid = EncoderQuality;
                        encoderParameters.Parameter[0].Type = EncoderParameterValueTypeLong;
                        encoderParameters.Parameter[0].NumberOfValues = 1;
                        ULONG quality = 40;
                        encoderParameters.Parameter[0].Value = &quality;

                        if (bitmap.Save(pStream, &encoderClsid, &encoderParameters) == Ok) {
                            // Read stream to vector
                            LARGE_INTEGER liZero = {};
                            ULARGE_INTEGER uliSize = {};
                            pStream->Seek(liZero, STREAM_SEEK_END, &uliSize);
                            pStream->Seek(liZero, STREAM_SEEK_SET, NULL);

                            buffer.resize((size_t)uliSize.QuadPart);
                            ULONG bytesRead = 0;
                            pStream->Read(buffer.data(), (ULONG)buffer.size(), &bytesRead);
                        }
                        pStream->Release();
                    }
                }
            }

            DeleteObject(hbmScreen);
            DeleteDC(hdcMemDC);
            ReleaseDC(NULL, hdcScreen);
        }

        GdiplusShutdown(gdiplusToken);
        return buffer;
    }

}
