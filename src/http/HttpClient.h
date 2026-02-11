#pragma once
#include <string>
#include <vector>
#ifndef _WIN32
typedef unsigned char BYTE;
#else
#include <windows.h>
#endif
namespace http {
class HttpClient {
public:
    HttpClient(const std::string& userAgent);
    ~HttpClient();
    std::string get(const std::string& server, const std::string& path, const std::string& headers = "");
    std::vector<BYTE> post(const std::string& server, const std::string& path, const std::vector<BYTE>& data, const std::string& headers = "");
private:
    std::string userAgent_;
#ifndef _WIN32
    std::vector<BYTE> request(const std::string& method, const std::string& server, const std::string& path, const std::vector<BYTE>& data, const std::string& headers);
#endif
};
}
