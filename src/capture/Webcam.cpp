#include "Webcam.h"
#include "../utils/Logger.h"
#include <mfapi.h>
#include <mfidl.h>
#include <mfplay.h>
#include <evr.h>
#include <gdiplus.h>
#include <vector>
#include <atlbase.h>
#include <algorithm>

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mf.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "evr.lib")

using namespace Gdiplus;

namespace capture {

namespace {
    class SampleGrabberCallback : public IMFSampleGrabberSinkCallback {
    public:
        SampleGrabberCallback() : refCount_(1), event_(NULL), buffer_(NULL), bufferLen_(0) {}
        virtual ~SampleGrabberCallback() {}

        STDMETHODIMP QueryInterface(REFIID iid, void** ppv) {
            if (iid == IID_IUnknown || iid == __uuidof(IMFSampleGrabberSinkCallback)) {
                *ppv = static_cast<IMFSampleGrabberSinkCallback*>(this);
                AddRef();
                return S_OK;
            }
            *ppv = NULL;
            return E_NOINTERFACE;
        }
        STDMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&refCount_); }
        STDMETHODIMP_(ULONG) Release() {
            ULONG count = InterlockedDecrement(&refCount_);
            if (count == 0) { delete this; }
            return count;
        }

        STDMETHODIMP OnClockStart(MFTIME /*hnsSystemTime*/, LONGLONG /*llClockStartOffset*/) { return S_OK; }
        STDMETHODIMP OnClockStop(MFTIME /*hnsSystemTime*/) { return S_OK; }
        STDMETHODIMP OnClockPause(MFTIME /*hnsSystemTime*/) { return S_OK; }
        STDMETHODIMP OnClockResume(MFTIME /*hnsSystemTime*/) { return S_OK; }
        STDMETHODIMP OnClockSetRate(MFTIME /*hnsSystemTime*/, float /*flRate*/) { return S_OK; }
        STDMETHODIMP OnClockRestart(MFTIME /*hnsSystemTime*/) { return S_OK; }
        STDMETHODIMP OnSetPresentationClock(IMFPresentationClock* /*pPresentationClock*/) { return S_OK; }
        STDMETHODIMP OnProcessSample(REFGUID /*guidMajorMediaType*/, DWORD /*dwSampleFlags*/, LONGLONG /*llSampleTime*/, LONGLONG /*llSampleDuration*/, const BYTE * pSampleBuffer, DWORD dwSampleSize) {
            std::lock_guard<std::mutex> lock(mutex_);
            bufferLen_ = dwSampleSize;
            buffer_ = new BYTE[dwSampleSize];
            memcpy(buffer_, pSampleBuffer, dwSampleSize);
            SetEvent(event_);
            return S_OK;
        }
        STDMETHODIMP OnShutdown() { return S_OK; }

        void WaitForSample(HANDLE event) { event_ = event; }
        BYTE* GetBuffer(DWORD* len) {
            *len = bufferLen_;
            BYTE* buf = buffer_;
            buffer_ = NULL;
            return buf;
        }

    private:
        ULONG refCount_;
        HANDLE event_;
        BYTE* buffer_;
        DWORD bufferLen_;
        std::mutex mutex_;
    };

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

    std::vector<BYTE> ConvertRawToJpeg(BYTE* rawData, UINT width, UINT height, UINT stride) {
        std::vector<BYTE> jpg;
        GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        if (GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Ok) return jpg;

        Bitmap bmp(width, height, stride, PixelFormat32bppRGB, rawData);

        CLSID encoderClsid;
        if (GetEncoderClsid(L"image/jpeg", &encoderClsid) >= 0) {
            IStream* pStream = NULL;
            CreateStreamOnHGlobal(NULL, TRUE, &pStream);
            EncoderParameters encoderParameters;
            encoderParameters.Count = 1;
            encoderParameters.Parameter[0].Guid = EncoderQuality;
            encoderParameters.Parameter[0].Type = EncoderParameterValueTypeLong;
            encoderParameters.Parameter[0].NumberOfValues = 1;
            ULONG quality = 40;
            encoderParameters.Parameter[0].Value = &quality;

            if (bmp.Save(pStream, &encoderClsid, &encoderParameters) == Ok) {
                LARGE_INTEGER liZero = {};
                ULARGE_INTEGER uliSize = {};
                pStream->Seek(liZero, STREAM_SEEK_END, &uliSize);
                pStream->Seek(liZero, STREAM_SEEK_SET, NULL);
                jpg.resize((size_t)uliSize.QuadPart);
                ULONG bytesRead = 0;
                pStream->Read(jpg.data(), (ULONG)jpg.size(), &bytesRead);
            }
            pStream->Release();
        }
        GdiplusShutdown(gdiplusToken);
        return jpg;
    }
}

nlohmann::json ListWebcamDevices() {
    nlohmann::json result = {{"devices", nlohmann::json::array()}};
    IMFAttributes* pAttrs = nullptr;
    IMFActivate** ppDevs = nullptr;
    UINT32 devCount = 0;

    HRESULT hr = MFStartup(MF_VERSION, MFSTARTUP_FULL);
    if (FAILED(hr)) {
        result["error"] = "MFStartup failed";
        return result;
    }

    hr = MFCreateAttributes(&pAttrs, 1);
    if (FAILED(hr)) {
        MFShutdown();
        return result;
    }

    hr = pAttrs->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                         MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
    if (FAILED(hr)) {
        pAttrs->Release();
        MFShutdown();
        return result;
    }

    hr = MFEnumDeviceSources(pAttrs, &ppDevs, &devCount);
    if (FAILED(hr) || devCount == 0) {
        result["devices"].push_back({{"index", 0}, {"name", "No devices"}, {"error", "Enumeration failed"}});
        if (pAttrs) pAttrs->Release();
        MFShutdown();
        return result;
    }

    for (UINT32 i = 0; i < devCount; ++i) {
        WCHAR* wszFriendly = nullptr;
        UINT32 cchFriendly = 0;
        hr = ppDevs[i]->GetAllocatedString(MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, &wszFriendly, &cchFriendly);

        std::string name = "Unnamed_" + std::to_string(i);
        if (SUCCEEDED(hr) && wszFriendly) {
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wszFriendly, -1, nullptr, 0, nullptr, nullptr);
            name.resize(utf8Len);
            WideCharToMultiByte(CP_UTF8, 0, wszFriendly, -1, &name[0], utf8Len, nullptr, nullptr);
            name.pop_back(); // null terminator
            CoTaskMemFree(wszFriendly);
        }

        nlohmann::json caps = nlohmann::json::array();

        IMFMediaSource* pSrc = nullptr;
        hr = ppDevs[i]->ActivateObject(IID_PPV_ARGS(&pSrc));
        if (SUCCEEDED(hr)) {
            IMFPresentationDescriptor* pPD = nullptr;
            if (SUCCEEDED(pSrc->CreatePresentationDescriptor(&pPD))) {
                BOOL fSelected;
                IMFStreamDescriptor* pSD = nullptr;
                if (SUCCEEDED(pPD->GetStreamDescriptorByIndex(0, &fSelected, &pSD))) {
                    IMFMediaTypeHandler* pHandler = nullptr;
                    if (SUCCEEDED(pSD->GetMediaTypeHandler(&pHandler))) {
                        DWORD cTypes = 0;
                        pHandler->GetMediaTypeCount(&cTypes);
                        for (DWORD t = 0; t < cTypes && t < 20; ++t) {
                            IMFMediaType* pType = nullptr;
                            if (SUCCEEDED(pHandler->GetMediaTypeByIndex(t, &pType))) {
                                UINT32 w = 0, h = 0;
                                MFGetAttributeSize(pType, MF_MT_FRAME_SIZE, &w, &h);

                                UINT32 num = 0, den = 0;
                                MFGetAttributeRatio(pType, MF_MT_FRAME_RATE, &num, &den);
                                float fps = (den != 0) ? static_cast<float>(num) / den : 0.0f;

                                GUID subType{};
                                pType->GetGUID(MF_MT_SUBTYPE, &subType);
                                std::string fmt = (subType == MFVideoFormat_MJPG) ? "MJPG" :
                                                  (subType == MFVideoFormat_YUY2) ? "YUY2" :
                                                  (subType == MFVideoFormat_NV12) ? "NV12" : "Other";

                                caps.push_back({
                                    {"width", w},
                                    {"height", h},
                                    {"fps", fps},
                                    {"format", fmt}
                                });

                                pType->Release();
                            }
                        }
                        pHandler->Release();
                    }
                    pSD->Release();
                }
                pPD->Release();
            }
            pSrc->Release();
        }

        result["devices"].push_back({
            {"index", static_cast<int>(i)},
            {"name", name},
            {"capabilities", caps}
        });
    }

    if (ppDevs) {
        for (UINT32 i = 0; i < devCount; ++i) ppDevs[i]->Release();
        CoTaskMemFree(ppDevs);
    }
    if (pAttrs) pAttrs->Release();
    MFShutdown();

    return result;
}

std::vector<BYTE> CaptureWebcamJPEG(int deviceIndex, const std::string& nameHint) {
    std::vector<BYTE> jpg;
    IMFActivate** ppDevices = NULL;
    UINT32 deviceCount = 0;
    CComPtr<IMFAttributes> pAttributes;
    CComPtr<IMFMediaSource> pSource;
    CComPtr<IMFPresentationDescriptor> pPD;
    CComPtr<IMFStreamDescriptor> pSD;
    CComPtr<IMFMediaTypeHandler> pHandler;
    CComPtr<IMFMediaType> pType;
    CComPtr<IMFActivate> pGrabberAct;
    CComPtr<IMFMediaSink> pSink;
    CComPtr<IMFTopology> pTopology;
    CComPtr<IMFTopologyNode> pSourceNode;
    CComPtr<IMFTopologyNode> pSinkNode;
    CComPtr<IMFMediaSession> pSession;
    HANDLE hEvent = NULL;
    SampleGrabberCallback* pCallback = NULL;

    HRESULT hr = MFStartup(MF_VERSION, MFSTARTUP_FULL);
    if (FAILED(hr)) {
        LOG_ERR("MFStartup failed.");
        return jpg;
    }

    MFCreateAttributes(&pAttributes, 1);
    pAttributes->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);

    hr = MFEnumDeviceSources(pAttributes, &ppDevices, &deviceCount);
    if (FAILED(hr) || deviceCount == 0) {
        LOG_ERR("No webcam devices found.");
    } else {
        int selectedIdx = deviceIndex;

        if (!nameHint.empty()) {
            std::string hintLower = nameHint;
            std::transform(hintLower.begin(), hintLower.end(), hintLower.begin(), [](unsigned char c){ return std::tolower(c); });

            for (UINT32 i = 0; i < deviceCount; ++i) {
                WCHAR* wszName = nullptr;
                UINT32 cch = 0;
                if (SUCCEEDED(ppDevices[i]->GetAllocatedString(MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, &wszName, &cch))) {
                    std::wstring wname(wszName);
                    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, &wname[0], (int)wname.size(), NULL, 0, NULL, NULL);
                    std::string utf8(utf8Len, 0);
                    WideCharToMultiByte(CP_UTF8, 0, &wname[0], (int)wname.size(), &utf8[0], utf8Len, NULL, NULL);
                    std::string lowerUtf8 = utf8;
                    std::transform(lowerUtf8.begin(), lowerUtf8.end(), lowerUtf8.begin(), ::tolower);

                    if (lowerUtf8.find(hintLower) != std::string::npos) {
                        selectedIdx = static_cast<int>(i);
                        CoTaskMemFree(wszName);
                        break;
                    }
                    CoTaskMemFree(wszName);
                }
            }
        }

        if (selectedIdx >= static_cast<int>(deviceCount)) {
            LOG_ERR("No matching device for hint '" + nameHint + "' or invalid index");
        } else {
            hr = ppDevices[selectedIdx]->ActivateObject(IID_PPV_ARGS(&pSource));
            if (SUCCEEDED(hr)) {
                hr = pSource->CreatePresentationDescriptor(&pPD);
            }
            if (SUCCEEDED(hr)) {
                BOOL fSelected;
                hr = pPD->GetStreamDescriptorByIndex(0, &fSelected, &pSD);
            }
            if (SUCCEEDED(hr)) {
                hr = pSD->GetMediaTypeHandler(&pHandler);
            }
            if (SUCCEEDED(hr)) {
                hr = MFCreateMediaType(&pType);
            }
            if (SUCCEEDED(hr)) {
                pType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
                pType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_MJPG);
                pType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
                MFSetAttributeSize(pType, MF_MT_FRAME_SIZE, 320, 240);
                MFSetAttributeRatio(pType, MF_MT_FRAME_RATE, 30, 1);
                MFSetAttributeRatio(pType, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
                hr = pHandler->SetCurrentMediaType(pType);
                if (FAILED(hr)) {
                    pType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
                    hr = pHandler->SetCurrentMediaType(pType);
                }
            }
            if (SUCCEEDED(hr)) {
                hr = pPD->SelectStream(0);
            }
            if (SUCCEEDED(hr)) {
                pCallback = new SampleGrabberCallback();
                hr = MFCreateSampleGrabberSinkActivate(pType, pCallback, &pGrabberAct);
            }
            if (SUCCEEDED(hr)) {
                hr = pGrabberAct->ActivateObject(IID_PPV_ARGS(&pSink));
            }
            if (SUCCEEDED(hr)) {
                hr = MFCreateTopology(&pTopology);
            }
            if (SUCCEEDED(hr)) {
                hr = MFCreateTopologyNode(MF_TOPOLOGY_SOURCESTREAM_NODE, &pSourceNode);
            }
            if (SUCCEEDED(hr)) {
                pSourceNode->SetUnknown(MF_TOPONODE_SOURCE, pSource);
                pSourceNode->SetUnknown(MF_TOPONODE_PRESENTATION_DESCRIPTOR, pPD);
                pSourceNode->SetUnknown(MF_TOPONODE_STREAM_DESCRIPTOR, pSD);
                pTopology->AddNode(pSourceNode);
                hr = MFCreateTopologyNode(MF_TOPOLOGY_OUTPUT_NODE, &pSinkNode);
            }
            if (SUCCEEDED(hr)) {
                pSinkNode->SetObject(pSink);
                pTopology->AddNode(pSinkNode);
                hr = pSourceNode->ConnectOutput(0, pSinkNode, 0);
            }
            if (SUCCEEDED(hr)) {
                hr = MFCreateMediaSession(NULL, &pSession);
            }
            if (SUCCEEDED(hr)) {
                hr = pSession->SetTopology(0, pTopology);
            }
            if (SUCCEEDED(hr)) {
                PROPVARIANT varStart;
                PropVariantInit(&varStart);
                hr = pSession->Start(&GUID_NULL, &varStart);
            }
            if (SUCCEEDED(hr)) {
                hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
                pCallback->WaitForSample(hEvent);
                DWORD wait = WaitForSingleObject(hEvent, 2000);
                if (wait == WAIT_OBJECT_0) {
                    DWORD len = 0;
                    BYTE* raw = pCallback->GetBuffer(&len);
                    if (raw) {
                        GUID subtype;
                        pType->GetGUID(MF_MT_SUBTYPE, &subtype);
                        if (subtype == MFVideoFormat_MJPG) {
                            jpg.assign(raw, raw + len);
                        } else {
                            UINT32 w, h;
                            MFGetAttributeSize(pType, MF_MT_FRAME_SIZE, &w, &h);
                            UINT32 stride = w * 4;
                            jpg = ConvertRawToJpeg(raw, w, h, stride);
                        }
                        delete[] raw;
                    }
                }
                pSession->Stop();
                pSession->Close();
            }
        }
    }

    if (hEvent) CloseHandle(hEvent);
    for (UINT32 i = 0; i < deviceCount; i++) ppDevices[i]->Release();
    CoTaskMemFree(ppDevices);
    MFShutdown();
    return jpg;
}

} // namespace capture
