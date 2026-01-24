#include "SocksProxy.h"
#include <iostream>

namespace network {

SocksProxy::SocksProxy() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

SocksProxy::~SocksProxy() {
    Stop();
    WSACleanup();
}

bool SocksProxy::Start(int port) {
    if (m_running) return false;
    m_running = true;
    m_listenThread = std::thread(&SocksProxy::ListenThread, this, port);
    return true;
}

void SocksProxy::Stop() {
    m_running = false;
    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }
    if (m_listenThread.joinable()) {
        m_listenThread.join();
    }
}

void SocksProxy::ListenThread(int port) {
    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) return;

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((u_short)port);

    if (bind(m_listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        return;
    }

    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        return;
    }

    while (m_running) {
        SOCKET client = accept(m_listenSocket, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (m_running) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        std::thread(&SocksProxy::HandleClient, this, client).detach();
    }
}

void SocksProxy::HandleClient(SOCKET client) {
    unsigned char buffer[512];
    
    // 1. Handshake
    if (recv(client, (char*)buffer, 2, 0) <= 0) { closesocket(client); return; }
    if (buffer[0] != 0x05) { closesocket(client); return; } // Only SOCKS5
    
    int nMethods = buffer[1];
    std::vector<unsigned char> methods(nMethods);
    recv(client, (char*)methods.data(), nMethods, 0);

    unsigned char response[] = { 0x05, 0x00 }; // No Auth
    send(client, (char*)response, 2, 0);

    // 2. Request
    if (recv(client, (char*)buffer, 4, 0) <= 0) { closesocket(client); return; }
    if (buffer[1] != 0x01) { // Only CONNECT
        unsigned char fail[] = { 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        send(client, (char*)fail, 10, 0);
        closesocket(client);
        return;
    }

    SOCKET target = INVALID_SOCKET;
    if (buffer[3] == 0x01) { // IPv4
        sockaddr_in targetAddr;
        targetAddr.sin_family = AF_INET;
        recv(client, (char*)&targetAddr.sin_addr, 4, 0);
        recv(client, (char*)&targetAddr.sin_port, 2, 0);
        
        target = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (connect(target, (sockaddr*)&targetAddr, sizeof(targetAddr)) == SOCKET_ERROR) {
            closesocket(target); target = INVALID_SOCKET;
        }
    } else if (buffer[3] == 0x03) { // Domain name
        unsigned char len;
        recv(client, (char*)&len, 1, 0);
        std::string domain(len, '\0');
        recv(client, (char*)domain.data(), len, 0);
        unsigned short port;
        recv(client, (char*)&port, 2, 0);

        addrinfo hints = { 0 }, *res;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domain.c_str(), std::to_string(ntohs(port)).c_str(), &hints, &res) == 0) {
            target = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (connect(target, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
                closesocket(target); target = INVALID_SOCKET;
            }
            freeaddrinfo(res);
        }
    }

    if (target == INVALID_SOCKET) {
        unsigned char fail[] = { 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        send(client, (char*)fail, 10, 0);
        closesocket(client);
        return;
    }

    unsigned char ok[] = { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    send(client, (char*)ok, 10, 0);

    // 3. Relay
    std::thread t1(SocksProxy::Relay, client, target);
    std::thread t2(SocksProxy::Relay, target, client);
    t1.join();
    t2.join();

    closesocket(client);
    closesocket(target);
}

void SocksProxy::Relay(SOCKET from, SOCKET to) {
    char buffer[4096];
    int bytes;
    while ((bytes = recv(from, buffer, sizeof(buffer), 0)) > 0) {
        if (send(to, buffer, bytes, 0) <= 0) break;
    }
    shutdown(from, SD_RECEIVE);
    shutdown(to, SD_SEND);
}

} // namespace network
