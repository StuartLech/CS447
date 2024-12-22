#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <cerrno>
#include <system_error>
#include <fstream>
#include <algorithm>

#define BACKLOG 10
#define MAXDATASIZE 100

void sigchld_handler(int s)
{
    (void)s;

    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

std::string toCamelCase(const std::string& input)
{
    std::string output;
    bool capitalize = true;

    for (char c : input) {
        if (std::isalpha(c)) {
            if (capitalize) {
                output += std::toupper(c);
            } else {
                output += std::tolower(c);
            }
            capitalize = !capitalize;
        } else {
            output += c;
        }
    }
    return output;
}

void logConnection(const std::string& clientIP)
{
    time_t now = time(nullptr); 
    tm* localTime = localtime(&now); 
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);
    std::cout << "[" << timestamp << "] Connection from: " << clientIP << std::endl;
}

void logDisconnection(const std::string& clientIP)
{
    time_t now = time(nullptr);  
    tm* localTime = localtime(&now); 
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);
    std::cout << "[" << timestamp << "] Client disconnected: " << clientIP << std::endl;
}

int main(int argc, char* argv[])
{
    int sockfd, new_fd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }

    std::string configFileName = argv[1];

    std::string port;
    std::ifstream configFile(configFileName);
    if (!configFile.is_open()) {
        std::cerr << "Error opening configuration file: " << configFileName << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        if (line.substr(0, 5) == "PORT=") {
            port = line.substr(5);
            break;
        }
    }
    configFile.close();

    if (port.empty()) {
        std::cerr << "Port number not found in configuration file!" << std::endl;
        return 1;
    }

    if ((rv = getaddrinfo(nullptr, port.c_str(), &hints, &servinfo)) != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    for (p = servinfo; p != nullptr; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            std::perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            throw std::system_error(errno, std::generic_category(), "setsockopt");
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            std::perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == nullptr) {
        std::cerr << "server: failed to bind" << std::endl;
        return 1;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        throw std::system_error(errno, std::generic_category(), "listen");
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        throw std::system_error(errno, std::generic_category(), "sigaction");
    }

    std::cout << "server: waiting for connections..." << std::endl;

    while (true) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size);
        if (new_fd == -1) {
            std::perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);
        // Log the connection
        logConnection(s);

        if (!fork()) {
            close(sockfd);

            char buf[MAXDATASIZE];
            int numbytes;

            while(true)
            {
                if ((numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0)) == -1) {
                    perror("recv");
                    exit(1);
                } else if (numbytes == 0) { // Client disconnected
                    logDisconnection(s);
                    break;
                }

            buf[numbytes] = '\0';

            std::string receivedMsg(buf);
            std::string camelCaseMsg = toCamelCase(receivedMsg);

            if (send(new_fd, camelCaseMsg.c_str(), camelCaseMsg.size(), 0) == -1)
                perror("send");
            }

            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }

    return 0;
}
