#include "HttpClient.h"
#include <stdexcept>
#include <iostream>
#include <vector>
#include <cstring>
#include <sstream>
#ifndef _WIN32
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#endif
namespace http {
HttpClient::HttpClient(const std::string& userAgent) : userAgent_(userAgent) {
#ifndef _WIN32
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
}
HttpClient::~HttpClient() {}
#ifndef _WIN32
std::string HttpClient::get(const std::string& server, const std::string& path, const std::string& headers) {
    std::vector<BYTE> resp = request("GET", server, path, {}, headers);
    return std::string(resp.begin(), resp.end());
}
std::vector<BYTE> HttpClient::post(const std::string& server, const std::string& path, const std::vector<BYTE>& data, const std::string& headers) {
    return request("POST", server, path, data, headers);
}
std::vector<BYTE> HttpClient::request(const std::string& method, const std::string& server, const std::string& path, const std::vector<BYTE>& data, const std::string& headers) {
    BIO* bio = BIO_new_ssl_connect(SSL_CTX_new(TLS_client_method()));
    SSL* ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    std::string conn = server + ":443";
    BIO_set_conn_hostname(bio, conn.c_str());
    if (BIO_do_connect(bio) <= 0) {
        BIO_free_all(bio);
        throw std::runtime_error("Failed to connect");
    }
    std::stringstream ss;
    ss << method << " " << path << " HTTP/1.1\r\nHost: " << server << "\r\nUser-Agent: " << userAgent_ << "\r\nConnection: close\r\n" << headers;
    if (method == "POST") ss << "Content-Length: " << data.size() << "\r\n";
    ss << "\r\n";
    std::string req = ss.str();
    BIO_write(bio, req.c_str(), req.length());
    if (method == "POST" && !data.empty()) BIO_write(bio, data.data(), data.size());
    std::vector<BYTE> response;
    char buf[4096];
    int n;
    while ((n = BIO_read(bio, buf, sizeof(buf))) > 0) response.insert(response.end(), buf, buf + n);
    BIO_free_all(bio);
    std::string rs(response.begin(), response.end());
    size_t pos = rs.find("\r\n\r\n");
    if (pos != std::string::npos) return std::vector<BYTE>(response.begin() + pos + 4, response.end());
    return response;
}
#endif
}
