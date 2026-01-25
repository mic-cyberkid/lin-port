#include "Webcam.h"
#include <string>
#include <vector>
#include <vfw.h>
#include <gdiplus.h>
#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

namespace capture {
namespace {
    int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT num = 0, size = 0;
        GetImageEncodersSize(&num, &size);
        if (size == 0) return -1;
        std::vector<BYTE> buffer(size);
        ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)buffer.data();
        GetImageEncoders(num, size, pImageCodecInfo);
        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[j].Clsid;
                return j;
            }
        }
        return -1;
    }

    std::vector<BYTE> ConvertBmpToJpeg(const std::string& bmpPath) {
        std::vector<BYTE> buffer;
        GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        if (GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Ok) return {};

        {
            std::wstring wPath(bmpPath.begin(), bmpPath.end());
            Bitmap* bitmap = new Bitmap(wPath.c_str());
            if (bitmap && bitmap->GetLastStatus() == Ok) {
                CLSID encoderClsid;
                if (GetEncoderClsid(L"image/jpeg", &encoderClsid) != -1) {
                    IStream* pStream = NULL;
                    if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
                        EncoderParameters encoderParameters;
                        encoderParameters.Count = 1;
                        encoderParameters.Parameter[0].Guid = EncoderQuality;
                        encoderParameters.Parameter[0].Type = EncoderParameterValueTypeLong;
                        encoderParameters.Parameter[0].NumberOfValues = 1;
                        ULONG quality = 40;
                        encoderParameters.Parameter[0].Value = &quality;

                        if (bitmap->Save(pStream, &encoderClsid, &encoderParameters) == Ok) {
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
            delete bitmap;
        }
        GdiplusShutdown(gdiplusToken);
        return buffer;
    }
}

    std::vector<BYTE> CaptureWebcamImage() {
        // Simplified VFW Capture
        // 1. Create Capture Window
        char windowName[] = "CamCap";
        HWND hWebcam = capCreateCaptureWindowA(windowName, WS_CHILD, 0, 0, 320, 240, GetDesktopWindow(), 0);

        if (!hWebcam) return {};

        std::vector<BYTE> buffer;

        // 2. Connect to driver 0
        if (SendMessage(hWebcam, WM_CAP_DRIVER_CONNECT, 0, 0)) {
            // 3. Grab Frame
            SendMessage(hWebcam, WM_CAP_GRAB_FRAME, 0, 0);

            // 4. Save to Clipboard or File?
            // VFW makes getting raw bytes hard without callback.
            // Easy way: Save to temp file (DIB)

            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            std::string bmpPath = std::string(tempPath) + "cam.bmp";

            if (SendMessage(hWebcam, WM_CAP_FILE_SAVEDIB, 0, (LPARAM)bmpPath.c_str())) {
                buffer = ConvertBmpToJpeg(bmpPath);
                DeleteFileA(bmpPath.c_str());
            }

            SendMessage(hWebcam, WM_CAP_DRIVER_DISCONNECT, 0, 0);
        }

        DestroyWindow(hWebcam);
        return buffer;
    }

}
