#include "WinHttpClient.h"
#include <stdexcept>
#include <vector>

namespace http {

WinHttpClient::WinHttpClient(const std::wstring& userAgent) {
    sessionHandle_ = WinHttpOpen(userAgent.c_str(),
                                 WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME,
                                 WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sessionHandle_) {
        throw std::runtime_error("Failed to open WinHTTP session.");
    }
}

WinHttpClient::~WinHttpClient() {
    if (sessionHandle_) {
        WinHttpCloseHandle(sessionHandle_);
    }
}

std::string WinHttpClient::get(const std::wstring& server, const std::wstring& path) {
    HINTERNET connectHandle = nullptr;
    HINTERNET requestHandle = nullptr;
    std::string response;

    connectHandle = WinHttpConnect(sessionHandle_, server.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connectHandle) {
        throw std::runtime_error("Failed to connect to server.");
    }

    requestHandle = WinHttpOpenRequest(connectHandle, L"GET", path.c_str(),
                                       NULL, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!requestHandle) {
        WinHttpCloseHandle(connectHandle);
        throw std::runtime_error("Failed to open request.");
    }

    if (!WinHttpSendRequest(requestHandle, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(requestHandle);
        WinHttpCloseHandle(connectHandle);
        throw std::runtime_error("Failed to send request.");
    }

    if (!WinHttpReceiveResponse(requestHandle, NULL)) {
        WinHttpCloseHandle(requestHandle);
        WinHttpCloseHandle(connectHandle);
        throw std::runtime_error("Failed to receive response.");
    }

    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(requestHandle, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<char> buffer(bytesAvailable);
        DWORD bytesRead = 0;
        if (WinHttpReadData(requestHandle, buffer.data(), bytesAvailable, &bytesRead)) {
            response.append(buffer.data(), bytesRead);
        }
    }

    WinHttpCloseHandle(requestHandle);
    WinHttpCloseHandle(connectHandle);

    return response;
}

std::vector<BYTE> WinHttpClient::post(const std::wstring& server, const std::wstring& path, const std::vector<BYTE>& data, const std::wstring& headers) {
    HINTERNET connectHandle = nullptr;
    HINTERNET requestHandle = nullptr;
    std::vector<BYTE> response;

    connectHandle = WinHttpConnect(sessionHandle_, server.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connectHandle) {
        throw std::runtime_error("Failed to connect to server.");
    }

    requestHandle = WinHttpOpenRequest(connectHandle, L"POST", path.c_str(),
                                       NULL, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!requestHandle) {
        WinHttpCloseHandle(connectHandle);
        throw std::runtime_error("Failed to open request.");
    }

    DWORD headerLen = headers.empty() ? 0 : static_cast<DWORD>(headers.length());
    LPCWSTR headerPtr = headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str();

    if (!WinHttpSendRequest(requestHandle, headerPtr, headerLen,
                            (LPVOID)data.data(), static_cast<DWORD>(data.size()), static_cast<DWORD>(data.size()), 0)) {
        WinHttpCloseHandle(requestHandle);
        WinHttpCloseHandle(connectHandle);
        throw std::runtime_error("Failed to send request.");
    }

    if (!WinHttpReceiveResponse(requestHandle, NULL)) {
        WinHttpCloseHandle(requestHandle);
        WinHttpCloseHandle(connectHandle);
        throw std::runtime_error("Failed to receive response.");
    }

    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(requestHandle, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<BYTE> buffer(bytesAvailable);
        DWORD bytesRead = 0;
        if (WinHttpReadData(requestHandle, buffer.data(), bytesAvailable, &bytesRead)) {
            response.insert(response.end(), buffer.begin(), buffer.begin() + bytesRead);
        }
    }

    WinHttpCloseHandle(requestHandle);
    WinHttpCloseHandle(connectHandle);

    return response;
}

} // namespace http
