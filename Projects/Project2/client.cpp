#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>
#include <algorithm>

// Constants
constexpr size_t MAXDATASIZE = 2048;

// Function to convert sockaddr to IP address
void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Convert string to uppercase
std::string toUpper(const std::string &str) {
    std::string upper_str = str;
    std::transform(upper_str.begin(), upper_str.end(), upper_str.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return upper_str;
}

// Function to handle receiving UDP statistics and heartbeat messages from the server
void receiveBroadcasts(std::atomic<bool>& running, int server_udp_port, int client_udp_port, const std::string& serverIP) {
    int sockfd;
    struct sockaddr_in addr;
    char buffer[MAXDATASIZE];

    // Create a UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return;
    }

    // Set up the address structure
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(client_udp_port);
    addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces

    // Bind the socket
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return;
    }

    std::cout << "[UDP] Listening for heartbeat and stats on UDP port " << client_udp_port << std::endl;

    while (running) {
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr*)&sender_addr, &addr_len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }
        buffer[n] = '\0'; // Null-terminate the string
        std::string msg(buffer);

        if (msg == "HEARTBEAT") {
            std::cout << "[UDP] Received HEARTBEAT from server." << std::endl;

            // Send heartbeat response back to the server
            struct sockaddr_in server_addr;
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(server_udp_port);
            server_addr.sin_addr.s_addr = inet_addr(serverIP.c_str()); // Use serverIP from configuration

            std::string response = "HEARTBEAT_RESPONSE";
            if (sendto(sockfd, response.c_str(), response.length(), 0,
                       (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                perror("sendto (HEARTBEAT_RESPONSE)");
            } else {
                std::cout << "[UDP] Sent HEARTBEAT_RESPONSE to server." << std::endl;
            }
        } else {
            std::cout << "Received stats: " << buffer << std::endl; // Display the stats
        }
    }

    close(sockfd); // Close the socket when done
}

// Function to handle receiving messages from the server
void receiveMessages(int sockfd, std::atomic<int>& messagesReceived, std::atomic<int>& bytesReceived) {
    char buf[MAXDATASIZE];
    int numbytes;
    while (true) {
        numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0);
        if (numbytes == -1) {
            perror("recv");
            exit(1);
        } else if (numbytes == 0) {
            std::cout << "Connection closed by server.\n";
            close(sockfd);
            exit(0);
        }
        buf[numbytes] = '\0';  // Null-terminate the received data
        std::cout << buf << std::endl;  // Display the message

        // Update statistics
        messagesReceived++;
        bytesReceived += numbytes;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: client <config_file>\n";
        return 1;
    }

    std::string serverIP, serverPort;
    std::atomic<int> messagesReceived(0); // Count messages received
    std::atomic<int> bytesReceived(0);    // Count bytes received
    std::atomic<bool> running(true);       // Control the running state

    // Read configuration from file
    std::ifstream configFile(argv[1]);
    if (!configFile.is_open()) {
        std::cerr << "Error opening config file: " << argv[1] << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        // Skip empty lines or comments
        if (line.empty() || line[0] == '#')
            continue;

        if (line.find("SERVER_IP=") == 0) {
            serverIP = line.substr(10);
        } else if (line.find("SERVER_PORT=") == 0) {
            serverPort = line.substr(12);
        }
    }
    configFile.close();

    int sockfd;
    struct addrinfo hints{}, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(serverIP.c_str(), serverPort.c_str(), &hints, &servinfo)) != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    // Loop through all the results and connect to the first we can
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        break;
    }

    if (p == nullptr) {
        std::cerr << "client: failed to connect\n";
        return 2;
    }

    char s[INET6_ADDRSTRLEN];
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
    std::cout << "client: connecting to " << s << std::endl;

    freeaddrinfo(servinfo);  // All done with this structure

    // After connecting to the server, get the local TCP port
    struct sockaddr_in local_addr;
    socklen_t addr_len_local = sizeof(local_addr);
    if (getsockname(sockfd, (struct sockaddr *)&local_addr, &addr_len_local) == -1) {
        perror("getsockname");
        return 1;
    }
    int tcp_port = ntohs(local_addr.sin_port);
    int client_udp_port = tcp_port + 1000; // Fixed offset

    // Send UDP port to the server
    std::string udp_port_msg = "UDPPORT " + std::to_string(client_udp_port) + "\n";
    if (send(sockfd, udp_port_msg.c_str(), udp_port_msg.length(), 0) == -1) {
        perror("send");
        close(sockfd);
        return 1;
    }
    std::cout << "[TCP] Sent UDP port " << client_udp_port << " to server." << std::endl;

    // Derive server's UDP port (TCP_PORT +1)
    int server_udp_port = tcp_port + 1;

    // Start a thread to receive UDP messages from the server
    std::thread udpThread(receiveBroadcasts, std::ref(running), server_udp_port, client_udp_port, serverIP);
    udpThread.detach();

    // Start a thread to receive messages from the server
    std::thread recvThread(receiveMessages, sockfd, std::ref(messagesReceived), std::ref(bytesReceived));
    recvThread.detach();

    std::string userInput;
    while (true) {
        std::getline(std::cin, userInput);
        if (userInput.empty()) continue;

        // Send user input as command to the server
        if (send(sockfd, userInput.c_str(), userInput.length(), 0) == -1) {
            perror("send");
            close(sockfd);
            running = false; // Signal threads to stop
            return 1;
        }

        // If the user types "QUIT", close the connection
        if (toUpper(userInput) == "QUIT") {
            std::cout << "Disconnecting from server...\n";
            running = false; // Signal threads to stop
            break;
        }
    }

    close(sockfd);
    return 0;
}
