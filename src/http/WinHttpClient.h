#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>

namespace http {

class WinHttpClient {
public:
    WinHttpClient(const std::wstring& userAgent);
    ~WinHttpClient();

    std::string get(const std::wstring& server, const std::wstring& path);
    std::vector<BYTE> post(const std::wstring& server, const std::wstring& path, const std::vector<BYTE>& data, const std::wstring& headers = L"");

private:
    HINTERNET sessionHandle_ = nullptr;
};

} // namespace http
