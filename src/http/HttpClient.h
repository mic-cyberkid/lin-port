#pragma once

#include <string>
#include <vector>
#include <cstdint>

typedef unsigned char BYTE;

namespace http {

class HttpClient {
public:
    HttpClient(const std::string& userAgent);
    ~HttpClient();

    std::string get(const std::string& server, const std::string& path, const std::string& headers = "");
    std::vector<BYTE> post(const std::string& server, const std::string& path, const std::vector<BYTE>& data, const std::string& headers = "");

private:
    std::string userAgent_;
    std::vector<BYTE> request(const std::string& method, const std::string& server, const std::string& path, const std::vector<BYTE>& data, const std::string& headers);
};

} // namespace http
