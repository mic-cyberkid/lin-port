#include "Screenshot.h"
#include <gdiplus.h>
#include <memory>
#include <vector>

#pragma comment(lib, "gdiplus.lib")

namespace capture {

    using namespace Gdiplus;

    int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT  num = 0;
        UINT  size = 0;

        GetImageEncodersSize(&num, &size);
        if (size == 0) return -1;

        std::unique_ptr<BYTE[]> buffer(new BYTE[size]);
        ImageCodecInfo* pImageCodecInfo = reinterpret_cast<ImageCodecInfo*>(buffer.get());
        GetImageEncoders(num, size, pImageCodecInfo);

        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[j].Clsid;
                return j;
            }
        }
        return -1;
    }

    std::vector<BYTE> CaptureScreenshotJPEG() {
        std::vector<BYTE> buffer;

        // Initialize GDI+ for this call (could be globalized but keeping it safe for now)
        GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        if (GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Ok) {
            return buffer;
        }

        {
            HDC hdcScreen = GetDC(NULL);
            HDC hdcMemDC = CreateCompatibleDC(hdcScreen);
            
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);

            HBITMAP hbmScreen = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
            HGDIOBJ hOld = SelectObject(hdcMemDC, hbmScreen);

            if (BitBlt(hdcMemDC, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY)) {
                
                // Create original bitmap
                Bitmap original(hbmScreen, NULL);
                
                // Scale down to 50% to reduce size significantly
                int newWidth = screenWidth / 2;
                int newHeight = screenHeight / 2;
                
                Bitmap resized(newWidth, newHeight, original.GetPixelFormat());
                Graphics graphics(&resized);
                
                // High quality scaling
                graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);
                graphics.DrawImage(&original, 0, 0, newWidth, newHeight);

                CLSID encoderClsid;
                if (GetEncoderClsid(L"image/jpeg", &encoderClsid) != -1) {
                    IStream* pStream = NULL;
                    if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
                        EncoderParameters encoderParameters;
                        encoderParameters.Count = 1;
                        encoderParameters.Parameter[0].Guid = EncoderQuality;
                        encoderParameters.Parameter[0].Type = EncoderParameterValueTypeLong;
                        encoderParameters.Parameter[0].NumberOfValues = 1;
                        ULONG quality = 40; // 40% quality is plenty for surveillance
                        encoderParameters.Parameter[0].Value = &quality;

                        if (resized.Save(pStream, &encoderClsid, &encoderParameters) == Ok) {
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

            SelectObject(hdcMemDC, hOld);
            DeleteObject(hbmScreen);
            DeleteDC(hdcMemDC);
            ReleaseDC(NULL, hdcScreen);
        }

        GdiplusShutdown(gdiplusToken);
        return buffer;
    }

}
