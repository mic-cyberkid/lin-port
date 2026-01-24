#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <atomic>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace network {

class SocksProxy {
public:
    SocksProxy();
    ~SocksProxy();

    bool Start(int port);
    void Stop();
    bool IsRunning() const { return m_running; }

private:
    void ListenThread(int port);
    void HandleClient(SOCKET clientSocket);
    static void Relay(SOCKET from, SOCKET to);

    std::atomic<bool> m_running{ false };
    std::thread m_listenThread;
    SOCKET m_listenSocket = INVALID_SOCKET;
};

} // namespace network
