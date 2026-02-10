#pragma once
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
typedef int SOCKET;
#define INVALID_SOCKET -1
#endif
#include <string>
#include <atomic>
#include <thread>

namespace network {

class SocksProxy {
public:
    SocksProxy();
    ~SocksProxy();

    bool Start(int port);
    void Stop();
    bool IsRunning() const { return isRunning_; }

private:
    std::atomic<bool> isRunning_;
    std::thread proxyThread_;
    SOCKET listenSocket_;

    void ProxyLoop(int port);
};

} // namespace network
