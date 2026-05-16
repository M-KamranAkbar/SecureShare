#pragma once
#include <string>

class Socket {
public:
    Socket();
    ~Socket();

    bool bindAndListen(int port, int backlog = 10);
    int  acceptClient();
    bool connectTo(const std::string& ip, int port);
    int  sendData(int fd, const std::string& data);
    std::string recvData(int fd);
    void closeSocket(int fd);

private:
    int server_fd;
};
