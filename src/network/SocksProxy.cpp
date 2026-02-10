#include "SocksProxy.h"
#include <vector>
#include <thread>
#include <cstring>
#ifndef _WIN32
#include <unistd.h>
#include <netdb.h>
#define SOCKET_ERROR -1
#define closesocket close
#define SD_RECEIVE SHUT_RD
#define SD_SEND SHUT_WR
#endif

namespace network {

SocksProxy::SocksProxy() : isRunning_(false), listenSocket_(INVALID_SOCKET) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

SocksProxy::~SocksProxy() {
    Stop();
#ifdef _WIN32
    WSACleanup();
#endif
}

bool SocksProxy::Start(int port) {
    if (isRunning_) return false;
    isRunning_ = true;
    proxyThread_ = std::thread(&SocksProxy::ProxyLoop, this, port);
    return true;
}

void SocksProxy::Stop() {
    isRunning_ = false;
    if (listenSocket_ != INVALID_SOCKET) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }
    if (proxyThread_.joinable()) {
        proxyThread_.join();
    }
}

void SocksProxy::ProxyLoop(int port) {
    listenSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket_ == INVALID_SOCKET) return;

    int opt = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)port);

    if (bind(listenSocket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        return;
    }

    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        return;
    }

    while (isRunning_) {
        SOCKET client = accept(listenSocket_, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (isRunning_) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        closesocket(client);
    }
}

} // namespace network
