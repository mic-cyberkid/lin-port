#include "SocksProxy.h"
#include <vector>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <algorithm>

#define SOCKET_ERROR -1
#define closesocket close

namespace network {

SocksProxy::SocksProxy() : isRunning_(false), listenSocket_(INVALID_SOCKET) {}

SocksProxy::~SocksProxy() {
    Stop();
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
        shutdown(listenSocket_, SHUT_RDWR);
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }
    if (proxyThread_.joinable()) {
        proxyThread_.join();
    }
}

static void HandleClient(SOCKET client) {
    unsigned char buffer[512];

    // 1. Negotiation
    if (recv(client, buffer, 2, 0) <= 0) { closesocket(client); return; }
    if (buffer[0] != 0x05) { closesocket(client); return; }
    int nmethods = buffer[1];
    std::vector<unsigned char> methods(nmethods);
    if (recv(client, methods.data(), nmethods, 0) <= 0) { closesocket(client); return; }

    // Support only 'no authentication' (0x00)
    buffer[0] = 0x05;
    buffer[1] = 0x00;
    if (send(client, buffer, 2, 0) <= 0) { closesocket(client); return; }

    // 2. Request
    if (recv(client, buffer, 4, 0) <= 0) { closesocket(client); return; }
    if (buffer[0] != 0x05 || buffer[1] != 0x01) { // 0x01 = CONNECT
        buffer[1] = 0x07; // Command not supported
        send(client, buffer, 10, 0); // Simplified error response
        closesocket(client); return;
    }

    SOCKET target = INVALID_SOCKET;
    if (buffer[3] == 0x01) { // IPv4
        sockaddr_in targetAddr;
        std::memset(&targetAddr, 0, sizeof(targetAddr));
        targetAddr.sin_family = AF_INET;
        if (recv(client, &targetAddr.sin_addr, 4, 0) <= 0) { closesocket(client); return; }
        if (recv(client, &targetAddr.sin_port, 2, 0) <= 0) { closesocket(client); return; }

        target = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(target, (sockaddr*)&targetAddr, sizeof(targetAddr)) < 0) {
            buffer[1] = 0x04; // Host unreachable
            send(client, buffer, 10, 0);
            closesocket(client); if (target != INVALID_SOCKET) closesocket(target); return;
        }
    } else if (buffer[3] == 0x03) { // Domain name
        unsigned char len;
        if (recv(client, &len, 1, 0) <= 0) { closesocket(client); return; }
        std::vector<char> domain(len + 1, 0);
        if (recv(client, domain.data(), len, 0) <= 0) { closesocket(client); return; }
        unsigned short port;
        if (recv(client, &port, 2, 0) <= 0) { closesocket(client); return; }

        addrinfo hints, *res;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domain.data(), std::to_string(ntohs(port)).c_str(), &hints, &res) != 0) {
            buffer[1] = 0x04;
            send(client, buffer, 10, 0);
            closesocket(client); return;
        }
        target = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (connect(target, res->ai_addr, res->ai_addrlen) < 0) {
            freeaddrinfo(res);
            buffer[1] = 0x04;
            send(client, buffer, 10, 0);
            closesocket(client); if (target != INVALID_SOCKET) closesocket(target); return;
        }
        freeaddrinfo(res);
    } else {
        buffer[1] = 0x08; // Address type not supported
        send(client, buffer, 10, 0);
        closesocket(client); return;
    }

    // 3. Response Success
    buffer[1] = 0x00; // Success
    buffer[2] = 0x00;
    buffer[3] = 0x01; // IPv4
    std::memset(buffer + 4, 0, 6); // BND.ADDR and BND.PORT
    if (send(client, buffer, 10, 0) <= 0) { closesocket(client); closesocket(target); return; }

    // 4. Data Transfer (Relay)
    struct pollfd fds[2];
    fds[0].fd = client;
    fds[0].events = POLLIN;
    fds[1].fd = target;
    fds[1].events = POLLIN;

    while (true) {
        int ret = poll(fds, 2, -1);
        if (ret <= 0) break;

        bool done = false;
        for (int i = 0; i < 2; ++i) {
            if (fds[i].revents & POLLIN) {
                int n = recv(fds[i].fd, buffer, sizeof(buffer), 0);
                if (n <= 0) { done = true; break; }
                if (send(fds[1 - i].fd, buffer, n, 0) <= 0) { done = true; break; }
            }
            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { done = true; break; }
        }
        if (done) break;
    }

    closesocket(client);
    closesocket(target);
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
        struct pollfd pfd;
        pfd.fd = listenSocket_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 500); // 500ms timeout to check isRunning_

        if (ret > 0 && (pfd.revents & POLLIN)) {
            SOCKET client = accept(listenSocket_, NULL, NULL);
            if (client != INVALID_SOCKET) {
                std::thread(HandleClient, client).detach();
            }
        } else if (ret < 0 && errno != EINTR) {
            break;
        }
    }
}

} // namespace network
