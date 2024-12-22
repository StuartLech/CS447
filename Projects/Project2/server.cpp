#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <vector>
#include <thread>
#include <mutex>
#include <fcntl.h>
#include <sys/select.h>
#include <algorithm>
#include <chrono>

// Global variables

struct ClientInfo {
    std::string nickname;
    std::string ip_address;
    int udp_port;
    bool registered;
    bool away;
    std::string away_message;
    std::chrono::time_point<std::chrono::steady_clock> last_heartbeat;
};

fd_set master_fds; // File descriptor set for select
int fdmax;

std::map<int, ClientInfo> clients; // Keyed by client_fd
std::map<std::string, std::set<int>> channels;
std::mutex client_mutex;
std::map<std::string, std::string> channel_topics;
std::map<int, int> user_modes; // Track user modes for each client
std::map<std::string, int> channel_modes;

int tcp_port;
int heartbeat_interval;
int stats_interval;

// Constants
#define MAXDATASIZE 2048
#define BACKLOG 10

// Numeric Reply Codes
const int RPL_WELCOME = 001;
const int RPL_YOURHOST = 002;
const int RPL_MYINFO = 004;
const int RPL_LIST = 322;
const int RPL_LISTEND = 323;
const int RPL_AWAY = 301;

// Error Reply Codes
const int ERR_NOSUCHNICK = 401;
const int ERR_ALREADYREGISTRED = 405;
const int ERR_NOSUCHCHANNEL = 403;
const int ERR_CANNOTSENDTOCHAN = 404;
const int ERR_NONICKNAMEGIVEN = 431;
const int ERR_ERRONEUSNICKNAME = 432;
const int ERR_NICKNAMEINUSE = 433;
const int ERR_NEEDMOREPARAMS = 461;
const int ERR_UMODEUNKNOWNFLAG = 501;
const int ERR_USERSDONTMATCH = 502;

const int RPL_UMODEIS = 221;

// Define user modes
enum UserMode {
    AWAY = 0b00000001,      // a
    INVISIBLE = 0b00000010, // i
    WALLOPS = 0b00000100,   // w
};

// Mode flags
const int MODE_AWAY = 1 << 0;       // 0b001
const int MODE_INVISIBLE = 1 << 1;  // 0b010
const int MODE_WALLOPS = 1 << 2;    // 0b100

const int CHANNEL_MODE_ANONYMOUS = 1 << 0;
const int CHANNEL_MODE_PRIVATE = 1 << 1;
const int CHANNEL_MODE_SECRET = 1 << 2;

// Function prototypes
void logMessage(const std::string &msg);
void handleClientData(int client_fd);
std::string toUpper(const std::string &str);
void handleCommand(int client_fd, const std::string &msg);
void handleNick(int client_fd, const std::string &nick);
void handleUser(int client_fd, const std::string &user, const std::string &mode_str, const std::string &unused, const std::string &realname);
void handleMode(int client_fd, const std::string &target, const std::string &modes);
void handleJoin(int client_fd, const std::string &channel);
void handleTopic(int client_fd, const std::string &channel, const std::string &topic);
void handleList(int client_fd, const std::string &mask);
void handlePart(int client_fd, const std::string &channel);
void handleNames(int client_fd, const std::string &channel);
void handlePrivmsg(int client_fd, const std::string &target, const std::string &message);
void handleQuit(int client_fd);
void sendWelcomeMessage(int client_fd, const std::string &nickname);
bool loadConfig(const std::string &configFile);
void broadcastServerStats(int udp_sock, int server_udp_port);
bool isValidNickname(const std::string &nick);
void sendWallops(const std::string &message);
void triggerWallops(const std::string &message);
void heartbeatThread(int udp_sock, int server_udp_port);
void receiveHeartbeatResponses(int udp_sock, int server_udp_port);

// Function implementations

bool loadConfig(const std::string &configFile) {
    std::ifstream config(configFile);
    if (!config.is_open()) {
        std::cerr << "Could not open config file: " << configFile << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(config, line)) {
        // Skip empty lines or comments
        if (line.empty() || line[0] == '#')
            continue;

        std::istringstream iss(line);
        std::string key;
        if (std::getline(iss, key, '=')) {
            std::string value;
            if (std::getline(iss, value)) {
                // Trim whitespace
                key.erase(key.find_last_not_of(" \n\r\t") + 1);
                value.erase(0, value.find_first_not_of(" \n\r\t"));

                if (key == "TCP_PORT") {
                    tcp_port = std::stoi(value);
                } else if (key == "HEARTBEAT_INTERVAL") {
                    heartbeat_interval = std::stoi(value);
                } else if (key == "STATS_INTERVAL") {
                    stats_interval = std::stoi(value);
                }
            }
        }
    }

    config.close();
    return true;
}

void logMessage(const std::string &msg) {
    std::cout << "[LOG] " << msg << std::endl;
}

std::string toUpper(const std::string &str) {
    std::string upper_str = str;
    std::transform(upper_str.begin(), upper_str.end(), upper_str.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return upper_str;
}

bool isValidNickname(const std::string &nick) {
    if (nick.length() < 1 || nick.length() > 15) {
        return false;
    }
    for (char c : nick) {
        if (!std::isalnum(c)) {
            return false; // Nickname contains an invalid character
        }
    }
    return true;
}

void handleNick(int client_fd, const std::string &nick) {
    std::lock_guard<std::mutex> lock(client_mutex);

    if (nick.empty()) {
        std::string err_msg = std::to_string(ERR_NONICKNAMEGIVEN) + " :No nickname given\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    if (!isValidNickname(nick)) {
        std::string err_msg = std::to_string(ERR_ERRONEUSNICKNAME) + " " + nick + " :Erroneous nickname\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    for (const auto &client : clients) {
        if (client.second.nickname == nick) {
            std::string err_msg = std::to_string(ERR_NICKNAMEINUSE) + " :Nickname is already in use\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }
    }

    clients[client_fd].nickname = nick;

    if (clients[client_fd].registered) {
        sendWelcomeMessage(client_fd, nick);
    }
}

void handleUser(int client_fd, const std::string &user, const std::string &mode_str, const std::string &unused, const std::string &realname) {
    std::lock_guard<std::mutex> lock(client_mutex);

    if (user.empty() || mode_str.empty() || realname.empty()) {
        std::string err_msg = std::to_string(ERR_NEEDMOREPARAMS) + " :Not enough parameters\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    if (clients[client_fd].registered) {
        std::string err_msg = "You may not reregister\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    clients[client_fd].registered = true;

    if (!clients[client_fd].nickname.empty()) {
        sendWelcomeMessage(client_fd, clients[client_fd].nickname);
    }
}

void handleMode(int client_fd, const std::string &target, const std::string &modes) {
    std::lock_guard<std::mutex> lock(client_mutex);

    if (channels.find(target) != channels.end()) {
        bool add = true;
        std::string modes_processed;
        for (char mode : modes) {
            if (mode == '+') {
                add = true;
            } else if (mode == '-') {
                add = false;
            } else {
                int &current_mode = channel_modes[target];
                switch (mode) {
                    case 'a':
                        current_mode = add ? (current_mode | CHANNEL_MODE_ANONYMOUS) : (current_mode & ~CHANNEL_MODE_ANONYMOUS);
                        modes_processed += mode;
                        break;
                    case 'p':
                        current_mode = add ? (current_mode | CHANNEL_MODE_PRIVATE) : (current_mode & ~CHANNEL_MODE_PRIVATE);
                        modes_processed += mode;
                        break;
                    case 's':
                        current_mode = add ? (current_mode | CHANNEL_MODE_SECRET) : (current_mode & ~CHANNEL_MODE_SECRET);
                        modes_processed += mode;
                        break;
                    default:
                        std::string err_msg = std::to_string(ERR_UMODEUNKNOWNFLAG) + " :Unknown channel mode flag\n";
                        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
                        return;
                }
            }
        }
        if (!modes_processed.empty()) {
            std::string mode_response = std::to_string(RPL_UMODEIS) + " " + target + " :+" + modes_processed + "\n";
            send(client_fd, mode_response.c_str(), mode_response.length(), 0);
            logMessage("Set mode +" + modes_processed + " for channel " + target);
        }
    } else {
        auto it = clients.find(client_fd);
        if (it == clients.end() || it->second.nickname != target) {
            std::string err_msg = std::to_string(ERR_USERSDONTMATCH) + " :Cannot change modes for other users\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }

        bool add = true;
        std::string modes_processed;
        for (char mode : modes) {
            if (mode == '+') {
                add = true;
                continue;
            } else if (mode == '-') {
                add = false;
                continue;
            }

            int &current_mode = user_modes[client_fd];
            switch (mode) {
                case 'a':
                    if (add) {
                        it->second.away = true;
                        it->second.away_message = "User is away";
                    } else {
                        it->second.away = false;
                        it->second.away_message.clear();
                    }
                    modes_processed += mode;
                    break;
                case 'i':
                    current_mode = add ? (current_mode | MODE_INVISIBLE) : (current_mode & ~MODE_INVISIBLE);
                    modes_processed += mode;
                    break;
                case 'w':
                    current_mode = add ? (current_mode | MODE_WALLOPS) : (current_mode & ~MODE_WALLOPS);
                    modes_processed += mode;
                    break;
                default:
                    std::string err_msg = std::to_string(ERR_UMODEUNKNOWNFLAG) + " :Unknown user mode flag\n";
                    send(client_fd, err_msg.c_str(), err_msg.length(), 0);
                    return;
            }
        }

        if (!modes_processed.empty()) {
            std::string mode_response = std::to_string(RPL_UMODEIS) + " " + target + " :+" + modes_processed + "\n";
            send(client_fd, mode_response.c_str(), mode_response.length(), 0);
            logMessage("Set mode +" + modes_processed + " for user " + target);
        }
    }
}

void handleJoin(int client_fd, const std::string &channel) {
    std::lock_guard<std::mutex> lock(client_mutex);

    if (!clients[client_fd].registered) {
        std::string err_msg = "You must register first\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    int channel_mode = channel_modes[channel];
    if ((channel_mode & CHANNEL_MODE_PRIVATE) || (channel_mode & CHANNEL_MODE_SECRET)) {
        std::string err_msg = "Cannot join " + channel + " due to restricted mode\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    channels[channel].insert(client_fd);

    std::string username = clients[client_fd].nickname;
    std::string join_msg = username + " has joined the channel " + channel + "\n";

    for (int member_fd : channels[channel]) {
        if (member_fd != client_fd) {
            send(member_fd, join_msg.c_str(), join_msg.length(), 0);
        }
    }

    std::string response = std::to_string(RPL_LIST) + " " + username + " " + channel + " :You have joined the channel\n";
    send(client_fd, response.c_str(), response.length(), 0);
    logMessage(username + " joined channel " + channel);
}

void handleTopic(int client_fd, const std::string &channel, const std::string &topic) {
    std::lock_guard<std::mutex> lock(client_mutex);

    if (!clients[client_fd].registered || channels[channel].find(client_fd) == channels[channel].end()) {
        std::string err_msg = "You must be registered and a member of the channel to set/view the topic.\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    if (topic.empty()) {
        auto it = channel_topics.find(channel);
        std::string response = it != channel_topics.end() && !it->second.empty() ?
            "Current topic for " + channel + ": " + it->second + "\n" :
            "No topic set for " + channel + "\n";
        send(client_fd, response.c_str(), response.length(), 0);
        return;
    }

    if (topic == "") {
        channel_topics.erase(channel);
        std::string response = "Topic for " + channel + " has been cleared.\n";
        send(client_fd, response.c_str(), response.length(), 0);
        logMessage("Cleared topic for channel " + channel);
    } else {
        channel_topics[channel] = topic;
        std::string response = "Topic for " + channel + " set to: " + topic + "\n";

        for (int member_fd : channels[channel]) {
            send(member_fd, response.c_str(), response.length(), 0);
        }
        logMessage("Set topic for channel " + channel + " to \"" + topic + "\"");
    }
}

void handleList(int client_fd, const std::string &mask) {
    std::lock_guard<std::mutex> lock(client_mutex);
    std::string list_msg;

    for (const auto &channel : channels) {
        int channel_mode = channel_modes[channel.first];
        bool is_member = channel.second.find(client_fd) != channel.second.end();

        if ((channel_mode & CHANNEL_MODE_SECRET) && !is_member) {
            continue;
        }

        if ((channel_mode & CHANNEL_MODE_PRIVATE) && !is_member) {
            list_msg = std::to_string(RPL_LIST) + " " + clients[client_fd].nickname + " " + channel.first + " :Private channel\n";
        } else {
            list_msg = std::to_string(RPL_LIST) + " " + clients[client_fd].nickname + " " + channel.first + " :Public channel\n";
        }
        send(client_fd, list_msg.c_str(), list_msg.length(), 0);
    }

    std::string end_msg = std::to_string(RPL_LISTEND) + " " + clients[client_fd].nickname + " :End of LIST\n";
    send(client_fd, end_msg.c_str(), end_msg.length(), 0);
}

void handlePart(int client_fd, const std::string &channel) {
    std::lock_guard<std::mutex> lock(client_mutex);

    if (channels.find(channel) != channels.end()) {
        channels[channel].erase(client_fd);
        std::string part_msg = clients[client_fd].nickname + " has left the channel " + channel + "\n";
        for (int member_fd : channels[channel]) {
            send(member_fd, part_msg.c_str(), part_msg.length(), 0);
        }
        std::string response = "You have left the channel " + channel + "\n";
        send(client_fd, response.c_str(), response.length(), 0);
        logMessage(clients[client_fd].nickname + " left channel " + channel);
    } else {
        std::string err_msg = std::to_string(ERR_NOSUCHCHANNEL) + " :No such channel\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
    }
}

void handleNames(int client_fd, const std::string &channel) {
    std::lock_guard<std::mutex> lock(client_mutex);

    // Check if the channel exists
    auto channel_it = channels.find(channel);
    if (channel_it == channels.end()) {
        std::string err_msg = std::to_string(ERR_NOSUCHCHANNEL) + " :No such channel\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    int client_mode = user_modes[client_fd];
    int channel_mode = channel_modes[channel];

    // If the channel is secret and the client is not a member, do not show the channel at all
    if ((channel_mode & CHANNEL_MODE_SECRET) && channels[channel].find(client_fd) == channels[channel].end() && !(client_mode & MODE_WALLOPS)) {
        std::string err_msg = std::to_string(ERR_NOSUCHCHANNEL) + " :No such channel\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    // If the channel is private, only show it to members or users with WALLOPS mode
    if ((channel_mode & CHANNEL_MODE_PRIVATE) && channels[channel].find(client_fd) == channels[channel].end() && !(client_mode & MODE_WALLOPS)) {
        std::string err_msg = "Cannot view the names in a private channel\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        return;
    }

    // List names of channel members
    std::string names_list = "Users in channel " + channel + ":\n";
    for (int member_fd : channels[channel]) {
        int member_mode = user_modes[member_fd];

        // Only show users with INVISIBLE mode if the requesting client is a member, has WALLOPS mode, or the user is not in INVISIBLE mode
        if ((!(member_mode & MODE_INVISIBLE) || channels[channel].count(client_fd) || (client_mode & MODE_WALLOPS))) {
            if (channel_mode & CHANNEL_MODE_ANONYMOUS) {
                names_list += "anonymous ";
            } else {
                names_list += clients[member_fd].nickname + " ";
            }
        }
    }

    names_list += "\n";
    send(client_fd, names_list.c_str(), names_list.length(), 0);
}

void handlePrivmsg(int client_fd, const std::string &target, const std::string &message) {
    std::lock_guard<std::mutex> lock(client_mutex);

    if (channels.find(target) != channels.end()) {
        if (channels[target].find(client_fd) != channels[target].end()) {
            std::string msg = "Private message from " + clients[client_fd].nickname + ": " + message + "\n";
            for (const auto &user_fd : channels[target]) {
                if (user_fd != client_fd && !(user_modes[user_fd] & MODE_INVISIBLE)) {
                    send(user_fd, msg.c_str(), msg.length(), 0);
                }
            }
        } else {
            std::string err_msg = std::to_string(ERR_CANNOTSENDTOCHAN) + " :Cannot send to channel (not a member)\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        }
    } else {
        bool user_found = false;
        for (const auto &pair : clients) {
            if (pair.second.nickname == target) {
                user_found = true;

                if (pair.second.away) {
                    std::string away_msg = std::to_string(RPL_AWAY) + " " + target + " :" + pair.second.away_message + "\n";
                    send(client_fd, away_msg.c_str(), away_msg.length(), 0);
                }

                std::string msg = "Private message from " + clients[client_fd].nickname + ": " + message + "\n";
                send(pair.first, msg.c_str(), msg.length(), 0);
                break;
            }
        }

        if (!user_found) {
            std::string err_msg = std::to_string(ERR_NOSUCHNICK) + "/" + std::to_string(ERR_NOSUCHCHANNEL) + " " + clients[client_fd].nickname + " :No such nick/channel\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
        }
    }
}

void handleQuit(int client_fd) {
    std::lock_guard<std::mutex> lock(client_mutex);

    // Remove the client from all channels
    for (auto &channel : channels) {
        channel.second.erase(client_fd);
    }

    // Remove the client from the clients map
    std::string nickname = clients[client_fd].nickname;
    clients.erase(client_fd);

    // Remove client_fd from master_fds
    FD_CLR(client_fd, &master_fds);

    // Update fdmax if necessary
    if (client_fd == fdmax) {
        fdmax--;
        for (int i = fdmax; i >= 0; --i) {
            if (FD_ISSET(i, &master_fds)) {
                fdmax = i;
                break;
            }
        }
    }

    // Close the client's socket
    close(client_fd);

    logMessage(nickname + " has disconnected.");
}

void sendWelcomeMessage(int client_fd, const std::string &nickname) {
    std::string welcome_msg = ":" + nickname + " " + std::to_string(RPL_WELCOME) + " " + nickname + " :Welcome to the IRC server!\n";
    send(client_fd, welcome_msg.c_str(), welcome_msg.length(), 0);

    std::string your_host_msg = ":" + nickname + " " + std::to_string(RPL_YOURHOST) + " " + nickname + " :Your host is this_server, running version 1.0\n";
    send(client_fd, your_host_msg.c_str(), your_host_msg.length(), 0);

    std::string my_info_msg = ":" + nickname + " " + std::to_string(RPL_MYINFO) + " " + nickname + " :this_server 1.0 iokn\n";
    send(client_fd, my_info_msg.c_str(), my_info_msg.length(), 0);

    // Initialize last heartbeat time
    clients[client_fd].last_heartbeat = std::chrono::steady_clock::now();
    logMessage("Sent welcome messages to " + nickname);
}

void sendWallops(const std::string &message) {
    for (const auto &client : clients) {
        if (user_modes[client.first] & MODE_WALLOPS) {
            send(client.first, message.c_str(), message.length(), 0);
        }
    }
}

void triggerWallops(const std::string &message) {
    std::string wallops_message = "WALLOPS: " + message + "\n";
    sendWallops(wallops_message);
}

void broadcastServerStats(int udp_sock, int server_udp_port) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(stats_interval));

        std::lock_guard<std::mutex> lock(client_mutex);
        int connected_users = clients.size();
        int active_channels = channels.size();

        std::string stats_message = "Server Stats: Connected Users: " + std::to_string(connected_users) +
                                    ", Active Channels: " + std::to_string(active_channels) + "\n";

        for (const auto& client_pair : clients) {
            const ClientInfo& client_info = client_pair.second;
            if (client_info.registered && client_info.udp_port != 0) {
                struct sockaddr_in client_addr;
                memset(&client_addr, 0, sizeof(client_addr));
                client_addr.sin_family = AF_INET;
                client_addr.sin_port = htons(client_info.udp_port);
                inet_pton(AF_INET, client_info.ip_address.c_str(), &client_addr.sin_addr);

                if (sendto(udp_sock, stats_message.c_str(), stats_message.length(), 0,
                           (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
                    perror("sendto (stats)");
                } else {
                    logMessage("Sent stats to " + client_info.nickname + " at " + client_info.ip_address + ":" + std::to_string(client_info.udp_port));
                }
            }
        }
    }
}

void heartbeatThread(int udp_sock, int server_udp_port) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(heartbeat_interval));

        {
            std::lock_guard<std::mutex> lock(client_mutex);
            auto now = std::chrono::steady_clock::now();

            // Send heartbeat message to each client
            for (auto& client_pair : clients) {
                ClientInfo& client_info = client_pair.second;
                if (client_info.registered && client_info.udp_port != 0) {
                    struct sockaddr_in client_addr;
                    memset(&client_addr, 0, sizeof(client_addr));
                    client_addr.sin_family = AF_INET;
                    client_addr.sin_port = htons(client_info.udp_port);
                    inet_pton(AF_INET, client_info.ip_address.c_str(), &client_addr.sin_addr);

                    std::string heartbeat_msg = "HEARTBEAT";
                    if (sendto(udp_sock, heartbeat_msg.c_str(), heartbeat_msg.length(), 0,
                               (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
                        perror("sendto (heartbeat)");
                    } else {
                        logMessage("Sent HEARTBEAT to " + client_info.nickname + " at " + client_info.ip_address + ":" + std::to_string(client_info.udp_port));
                    }
                }
            }

            // Check for clients that have timed out
            for (auto it = clients.begin(); it != clients.end(); ) {
                ClientInfo& client_info = it->second;
                if (client_info.registered) {
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - client_info.last_heartbeat).count();
                    if (duration > 2 * heartbeat_interval) {
                        // Client has not responded, consider disconnected
                        int client_fd = it->first;
                        logMessage("Client " + client_info.nickname + " timed out due to missed heartbeats.");

                        // Remove from channels
                        for (auto& channel : channels) {
                            channel.second.erase(client_fd);
                        }

                        // Close socket and remove from FD set
                        close(client_fd);
                        FD_CLR(client_fd, &master_fds);

                        // Erase from clients map
                        it = clients.erase(it);
                        continue;
                    }
                }
                ++it;
            }
        }
    }
}

void receiveHeartbeatResponses(int udp_sock, int server_udp_port) {
    char buffer[1024];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (true) {
        ssize_t recv_len = recvfrom(udp_sock, buffer, sizeof(buffer) - 1, 0,
                                    (struct sockaddr*)&client_addr, &addr_len);
        if (recv_len > 0) {
            buffer[recv_len] = '\0';
            std::string msg(buffer);

            if (msg == "HEARTBEAT_RESPONSE") {
                std::string client_ip = inet_ntoa(client_addr.sin_addr);
                int client_udp_port = ntohs(client_addr.sin_port);

                std::lock_guard<std::mutex> lock(client_mutex);
                bool found = false;
                for (auto& client_pair : clients) {
                    ClientInfo& client_info = client_pair.second;
                    if (client_info.ip_address == client_ip && client_info.udp_port == client_udp_port) {
                        client_info.last_heartbeat = std::chrono::steady_clock::now();
                        logMessage("Received HEARTBEAT_RESPONSE from " + client_info.nickname);
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    logMessage("Received HEARTBEAT_RESPONSE from unknown client " + client_ip + ":" + std::to_string(client_udp_port));
                }
            }
        }
    }
}

void handleCommand(int client_fd, const std::string &msg) {
    std::istringstream iss(msg);
    std::string command;
    iss >> command;

    command = toUpper(command);

    if (command == "NICK") {
        std::string nick;
        iss >> nick;
        if (nick.empty()) {
            std::string err_msg = std::to_string(ERR_NONICKNAMEGIVEN) + " NICK :No nickname given.\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }
        handleNick(client_fd, nick);
    } else if (command == "MODE") {
        std::string nickname, modes;
        iss >> nickname >> modes;
        if (nickname.empty() || modes.empty()) {
            std::string err_msg = std::to_string(ERR_NEEDMOREPARAMS) + " MODE :Not enough parameters\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }
        handleMode(client_fd, nickname, modes);
    } else if (command == "USER") {
        std::string user, mode_str, unused, realname;
        iss >> user >> mode_str >> unused;
        std::getline(iss, realname);
        if (user.empty() || mode_str.empty() || realname.empty()) {
            std::string err_msg = std::to_string(ERR_NEEDMOREPARAMS) + " USER :Not enough parameters\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }
        handleUser(client_fd, user, mode_str, unused, realname.substr(1));
    } else if (command == "JOIN") {
        std::string channel;
        iss >> channel;
        if (channel.empty()) {
            std::string err_msg = std::to_string(ERR_NEEDMOREPARAMS) + " JOIN :Not enough parameters\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }
        handleJoin(client_fd, channel);
    } else if (command == "TOPIC") {
        std::string channel, topic;
        iss >> channel;
        if (channel.empty()) {
            std::string err_msg = std::to_string(ERR_NEEDMOREPARAMS) + " TOPIC :Not enough parameters\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }
        std::getline(iss, topic);
        handleTopic(client_fd, channel, topic.empty() ? "" : topic.substr(1));
    } else if (command == "LIST") {
        std::string mask;
        iss >> mask;
        handleList(client_fd, mask);
    } else if (command == "PART") {
        std::string channel;
        iss >> channel;
        if (channel.empty()) {
            std::string err_msg = std::to_string(ERR_NEEDMOREPARAMS) + " PART :Not enough parameters\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }
        handlePart(client_fd, channel);
    } else if (command == "PRIVMSG") {
        std::string target, message;
        iss >> target;
        std::getline(iss, message);
        if (target.empty() || message.empty()) {
            std::string err_msg = std::to_string(ERR_NEEDMOREPARAMS) + " PRIVMSG :Not enough parameters\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }
        handlePrivmsg(client_fd, target, message.substr(1));
    } else if (command == "NAMES") {
        std::string channel;
        iss >> channel;
        handleNames(client_fd, channel);
    } else if (command == "QUIT") {
        handleQuit(client_fd);
    } else if (command == "UDPPORT") {
        std::string udp_port_str;
        iss >> udp_port_str;
        if (udp_port_str.empty()) {
            std::string err_msg = "No UDP port provided\n";
            send(client_fd, err_msg.c_str(), err_msg.length(), 0);
            return;
        }
        int client_udp_port = std::stoi(udp_port_str);
        {
            std::lock_guard<std::mutex> lock(client_mutex);
            clients[client_fd].udp_port = client_udp_port;
        }
        std::string response = "UDP port set to " + udp_port_str + "\n";
        send(client_fd, response.c_str(), response.length(), 0);
        logMessage("Received UDP port " + udp_port_str + " from client_fd " + std::to_string(client_fd));
    } else {
        std::string err_msg = ":Unknown command\n";
        send(client_fd, err_msg.c_str(), err_msg.length(), 0);
    }
}

void handleClientData(int client_fd) {
    char buf[MAXDATASIZE];
    int numbytes = recv(client_fd, buf, MAXDATASIZE - 1, 0);

    if (numbytes > 0) {
        buf[numbytes] = '\0';
        handleCommand(client_fd, std::string(buf));
    } else if (numbytes == 0) {
        handleQuit(client_fd);
    } else {
        perror("recv");
    }
}

// Main function

int main() {
    if (!loadConfig("server.conf")) {
        std::cerr << "Failed to load configuration. Exiting." << std::endl;
        return 1;
    }

    int sockfd, new_fd;
    struct sockaddr_in my_addr;
    struct sockaddr_in their_addr;
    socklen_t sin_size;

    // Create TCP socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    // Allow reuse of address
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(tcp_port);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(my_addr.sin_zero), '\0', 8);

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    logMessage("Server started, waiting for connections...");

    // Derive server's UDP port
    int server_udp_port = tcp_port + 1;

    // Create UDP socket for heartbeat and stats
    int udp_sock;
    if ((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in udp_addr;
    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_port = htons(server_udp_port);
    udp_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udp_sock, (struct sockaddr*)&udp_addr, sizeof(udp_addr)) < 0) {
        perror("bind");
        exit(1);
    }

    logMessage("Server UDP port: " + std::to_string(server_udp_port));

    // Start threads
    std::thread stats_thread(broadcastServerStats, udp_sock, server_udp_port);
    stats_thread.detach();

    std::thread heartbeat_thread_instance(heartbeatThread, udp_sock, server_udp_port);
    heartbeat_thread_instance.detach();

    std::thread heartbeat_response_thread(receiveHeartbeatResponses, udp_sock, server_udp_port);
    heartbeat_response_thread.detach();

    FD_ZERO(&master_fds);
    FD_SET(sockfd, &master_fds);
    fdmax = sockfd;

    while (true) {
        fd_set read_fds = master_fds;

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(1);
        }

        for (int i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == sockfd) {
                    sin_size = sizeof(struct sockaddr_in);
                    if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size)) == -1) {
                        perror("accept");
                    } else {
                        FD_SET(new_fd, &master_fds);
                        if (new_fd > fdmax) {
                            fdmax = new_fd;
                        }
                        char client_ip[INET_ADDRSTRLEN];
                        inet_ntop(their_addr.sin_family, &their_addr.sin_addr, client_ip, sizeof(client_ip));

                        ClientInfo client_info;
                        client_info.ip_address = client_ip;
                        client_info.registered = false;
                        client_info.udp_port = 0;
                        client_info.nickname = "";

                        {
                            std::lock_guard<std::mutex> lock(client_mutex);
                            clients[new_fd] = client_info;
                        }

                        logMessage("New connection established from " + client_info.ip_address);
                    }
                } else {
                    handleClientData(i);
                }
            }
        }
    }

    return 0;
}
