#include "Webcam.h"
#include <string>
#include "../utils/Logger.h"

// Note: Real VFW or MediaFoundation implementation is verbose.
// For Phase 4 verification, we will return a stub or error if no camera.
// To truly port the functionality, we would implement MF here. 
// Given the constraints and the goal of "faithful functional port", 
// we will assume for this specific iteration that we are providing the structure 
// and a stub, as full MF implementation is outside the immediate scope of a 
// single tool call block without blowing up complexity.
// 
// However, I will check if I can add a simple VFW implementation.
// VFW is deprecated but often still works for basic webcams.

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
        
        if (!hWebcam) {
            LOG_ERR("Failed to create capture window.");
            return {};
        }

        std::vector<BYTE> buffer;

        // 2. Connect to driver 0
        if (capDriverConnect(hWebcam, 0)) {
            Sleep(200); // Allow driver to connect
            // 3. Grab Frame
            if (capGrabFrame(hWebcam)) {
                // 4. Save to temp file (DIB)
                char tempPath[MAX_PATH];
                GetTempPathA(MAX_PATH, tempPath);
                std::string bmpPath = std::string(tempPath) + "cam.bmp";

                if (capFileSaveDIB(hWebcam, bmpPath.c_str())) {
                    buffer = ConvertBmpToJpeg(bmpPath);
                    DeleteFileA(bmpPath.c_str());
                } else {
                    LOG_ERR("Failed to save DIB from webcam.");
                }
            } else {
                LOG_ERR("Failed to grab frame from webcam.");
            }

            capDriverDisconnect(hWebcam);
        } else {
            LOG_ERR("Failed to connect to webcam driver.");
        }
        
        DestroyWindow(hWebcam);
        return buffer;
    }

}
