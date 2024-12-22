#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

constexpr size_t MAXDATASIZE = 100;

void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "usage: client client.conf\n";
        return 1;
    }

    // Read configuration from file
    std::string serverIP, serverPort;
    std::ifstream configFile(argv[1]);
    if (!configFile.is_open()) {
        std::cerr << "Error opening config file: " << argv[1] << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        if (line.find("SERVER_IP=") == 0) {
            serverIP = line.substr(10);
        } else if (line.find("SERVER_PORT=") == 0) {
            serverPort = line.substr(12);
        }
    }
    configFile.close();

    if (serverIP.empty() || serverPort.empty()) {
        std::cerr << "Invalid config file format.\n";
        return 1;
    }

    // Set up connection hints
    addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Get address information
    int rv = getaddrinfo(serverIP.c_str(), serverPort.c_str(), &hints, &servinfo);
    if (rv != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    int sockfd;
    // Loop through results and try to connect
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client: connect");
            close(sockfd);
            continue;
        }

        break;
    }

    if (p == nullptr) {
        std::cerr << "client: failed to connect\n";
        return 2;
    }

    // Display connection information
    char s[INET6_ADDRSTRLEN];
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
    std::cout << "client: connecting to " << s << std::endl;

    freeaddrinfo(servinfo);

    char buf[MAXDATASIZE];
    std::string userInput;

    // Interactive loop for sending and receiving messages
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, userInput);

        if (userInput == "exit") {
            break; // Exit the loop if the user types "exit"
        }

        if (send(sockfd, userInput.c_str(), userInput.size(), 0) == -1) {
            perror("send");
            break;
        }

        int numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0);
        if (numbytes == -1) {
            perror("recv");
            break;
        } else if (numbytes == 0) {
            std::cout << "Server closed the connection.\n";
            break;
        }

        buf[numbytes] = '\0';
        std::cout << "Server: " << buf << std::endl;
    }

    close(sockfd);
    return 0;
}