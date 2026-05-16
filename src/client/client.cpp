#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

#define SERVER_IP "127.0.0.1"
#define PORT 8080

string sendCommand(const string& cmd) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        return "ERROR: Cannot connect to server";

    send(sock, cmd.c_str(), cmd.size(), 0);
    shutdown(sock, SHUT_WR);

    string response;
    char buf[1024];
    int n;
    while ((n = recv(sock, buf, sizeof(buf)-1, 0)) > 0) {
        buf[n] = 0;
        response += buf;
    }
    close(sock);
    return response;
}

int main() {
    cout << "========================================" << endl;
    cout << "  SECURESHARE CLIENT v2.0" << endl;
    cout << "  Connected to " << SERVER_IP << ":" << PORT << endl;
    cout << "========================================" << endl;
    cout << "Commands:" << endl;
    cout << "  REGISTER user:pass" << endl;
    cout << "  LOGIN user:pass" << endl;
    cout << "  UPLOAD token:file:content" << endl;
    cout << "  DOWNLOAD token:file" << endl;
    cout << "  MYFILES token" << endl;
    cout << "  DELETE token:file" << endl;
    cout << "  EXIT" << endl;
    cout << "========================================\n" << endl;

    string input;
    while (true) {
        cout << "> ";
        getline(cin, input);
        if (input == "EXIT" || input == "exit") break;
        if (input.empty()) continue;
        cout << sendCommand(input) << endl;
    }
    return 0;
}
