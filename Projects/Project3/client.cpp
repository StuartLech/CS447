// client.cpp

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h> 
#include <openssl/aes.h> 
#include <openssl/bio.h> 
#include <openssl/buffer.h> 
#include <ncurses.h>    

constexpr size_t MAXDATASIZE = 1024;

#define DEBUG_MODE 1  // Set to 0 to disable debug prints

// Function to get the IPv4 or IPv6 address
void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Base64 Encode function
std::string base64Encode(const std::string& input) {
    BIO* bio, *b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    // Disable newlines - write everything in one line
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    // Write the input data
    BIO_write(bio, input.data(), input.length());
    BIO_flush(bio);

    // Get the output from the BIO
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string output(bufferPtr->data, bufferPtr->length);

    // Clean up
    BIO_free_all(bio);

    return output;
}

// Base64 Decode function
std::string base64Decode(const std::string& input) {
    BIO* bio, *b64;
    int decodeLen = input.length();
    int maxDecodedLen = decodeLen * 3 / 4 + 1;
    char* buffer = new char[maxDecodedLen];
    memset(buffer, 0, maxDecodedLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), decodeLen);
    // Disable newlines - read everything in one line
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    int decodedLength = BIO_read(bio, buffer, decodeLen);
    if (decodedLength <= 0) {
        // Handle error
        BIO_free_all(bio);
        delete[] buffer;
        return "";
    }

    std::string output(buffer, decodedLength);

    // Clean up
    BIO_free_all(bio);
    delete[] buffer;

    return output;
}

// Encrypt data using AES-256-CBC and then Base64 encode
std::string encryptData(const std::string& plaintext, const std::string& preSharedKey) {
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char key[32]; // 256-bit key

    // Derive the key from the pre-shared key using SHA-256
    SHA256(reinterpret_cast<const unsigned char*>(preSharedKey.c_str()), preSharedKey.length(), key);

    // Initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    // Allocate ciphertext buffer
    std::vector<unsigned char> ciphertext(plaintext.length() + AES_BLOCK_SIZE);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        std::cerr << "Error initializing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length())) {
        std::cerr << "Error during encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Convert ciphertext to string
    std::string cipherStr(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);

    // Base64 encode the ciphertext
    return base64Encode(cipherStr);
}

// Decrypt data using AES-256-CBC after Base64 decoding
std::string decryptData(const std::string& base64Ciphertext, const std::string& preSharedKey) {
    // Base64 decode the ciphertext
    std::string ciphertext = base64Decode(base64Ciphertext);

    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char key[32]; // 256-bit key

    // Derive the key from the pre-shared key using SHA-256
    SHA256(reinterpret_cast<const unsigned char*>(preSharedKey.c_str()), preSharedKey.length(), key);

    // Initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    // Allocate plaintext buffer
    std::vector<unsigned char> plaintext(ciphertext.length() + AES_BLOCK_SIZE);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        std::cerr << "Error initializing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length())) {
        std::cerr << "Error during decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "Error finalizing decryption" << std::endl;
        ERR_print_errors_fp(stderr); // Print detailed OpenSSL errors
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Return the plaintext as a string
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

// Tokenizes a string using a delimiter and returns the tokens as a vector
std::vector<std::string> tokenizeString(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> tokens;
    std::string::size_type start = 0, end;
    size_t delimiterLength = delimiter.length();
    while ((end = str.find(delimiter, start)) != std::string::npos) {
        tokens.emplace_back(str, start, end - start);
        start = end + delimiterLength;
    }
    tokens.emplace_back(str, start);
    return tokens;
}

// Function to display a centered message in a window
void displayCenteredMessage(WINDOW* win, int startY, const std::string& message) {
    int width = getmaxx(win);
    mvwprintw(win, startY, (width - message.length()) / 2, "%s", message.c_str());
}

// Function to trim whitespace from a string
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (std::string::npos == first) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
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

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Set TLS version to TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Enable SSL Certificate Verification

    // Load the server's certificate as a trusted CA
    if (SSL_CTX_load_verify_locations(ctx, "p3server.crt", nullptr) <= 0) {
        std::cerr << "Error loading server certificate as trusted CA" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Set verification mode to verify the peer's certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    // Set the verification depth (optional, default is 1)
    SSL_CTX_set_verify_depth(ctx, 4);

    // Set up connection hints
    addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Get address information
    int rv = getaddrinfo(serverIP.c_str(), serverPort.c_str(), &hints, &servinfo);
    if (rv != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        SSL_CTX_free(ctx);
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
        SSL_CTX_free(ctx);
        return 2;
    }

    // Create SSL structure and connect
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL connection failed\n";
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Verify the server's certificate
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        std::cerr << "SSL certificate verification failed: " << SSL_get_verify_result(ssl) << std::endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE); // Enable keypad for stdscr

    // Display connection information
    char s_addr[INET6_ADDRSTRLEN];
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s_addr, sizeof s_addr);

    int height, width;
    getmaxyx(stdscr, height, width);

    WINDOW* connWin = newwin(3, width, 0, 0);
    box(connWin, 0, 0);
    displayCenteredMessage(connWin, 1, "Connected to server at " + std::string(s_addr));
    wrefresh(connWin);

    freeaddrinfo(servinfo);

    char buf[MAXDATASIZE];
    std::string userInput;

    // Pre-shared key for encryption
    const std::string PRE_SHARED_KEY = "F24447TG";

    // Authentication sequence
    bool authenticated = false;
    while (!authenticated) {
        // Create a window for login
        WINDOW* loginWin = newwin(10, 50, (height - 10) / 2, (width - 50) / 2);
        box(loginWin, 0, 0);
        mvwprintw(loginWin, 1, 2, "Login to the Book Management System");

        // Username input
        mvwprintw(loginWin, 3, 2, "Username: ");
        char username[50];
        echo();
        wgetnstr(loginWin, username, sizeof(username) - 1);
        noecho();

        // Send USER command to server
        std::string userCommand = "USER " + std::string(username);
        if (SSL_write(ssl, userCommand.c_str(), userCommand.size()) <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }

        int numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
        if (numbytes <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        buf[numbytes] = '\0';
        std::string serverResponse(buf);

        // Password input
        mvwprintw(loginWin, 5, 2, "Password: ");
        char password[50];
        noecho();
        wgetnstr(loginWin, password, sizeof(password) - 1);
        echo();

        // Convert password to std::string
        std::string passwordStr(password);

        // Print the original password (for demonstration)
        #if DEBUG_MODE
        // Redirect debug prints to a log file
        std::ofstream debugLog("client_debug.log", std::ios::app);
        debugLog << "Original password: " << passwordStr << std::endl;
        #endif

        // Base64 encode the password
        std::string base64Password = base64Encode(passwordStr);

        // Print the base64-encoded password
        #if DEBUG_MODE
        debugLog << "Base64-encoded password: " << base64Password << std::endl;
        debugLog.close();
        #endif

        // Encrypt and send PASS command
        std::string encryptedPassword = encryptData(base64Password, PRE_SHARED_KEY);
        std::string passCommand = "PASS " + encryptedPassword;

        if (SSL_write(ssl, passCommand.c_str(), passCommand.size()) <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }

        numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
        if (numbytes <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        buf[numbytes] = '\0';
        serverResponse = buf;

        // Handle server response
        if (serverResponse == "230 User logged in, proceed") {
            authenticated = true;
            delwin(loginWin);
        } else if (serverResponse.find("New user created. Encrypted password: ") != std::string::npos) {
            // Extract encrypted password from server response
            size_t pos = serverResponse.find("Encrypted password: ");
            if (pos != std::string::npos) {
                pos += strlen("Encrypted password: ");
                std::string encryptedPasswordFromServer = serverResponse.substr(pos);

                // Remove any trailing messages
                size_t endPos = encryptedPasswordFromServer.find("\n");
                if (endPos != std::string::npos) {
                    encryptedPasswordFromServer = encryptedPasswordFromServer.substr(0, endPos);
                }

                // Trim any whitespace
                encryptedPasswordFromServer = trim(encryptedPasswordFromServer);

                // Decrypt the password
                std::string decryptedPassword = decryptData(encryptedPasswordFromServer, PRE_SHARED_KEY);

                // Base64 decode the password
                std::string newPassword = base64Decode(decryptedPassword);

                mvwprintw(loginWin, 7, 2, "Your new password is: %s", newPassword.c_str());
                mvwprintw(loginWin, 8, 2, "Please reconnect and login with your new credentials.");
                wrefresh(loginWin);

                // Wait for user to press a key
                wgetch(loginWin);

                // Close the connection and exit
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sockfd);
                SSL_CTX_free(ctx);
                delwin(loginWin);
                endwin();
                return 0;
            }
        } else {
            mvwprintw(loginWin, 7, 2, "Authentication failed. Please try again.");
            wrefresh(loginWin);
            // Wait for user to press a key
            wgetch(loginWin);
            delwin(loginWin);
        }
    }

    // Main menu loop
    bool exitProgram = false;
    int mode = 0; // 0: Default, 2: Search, 3: Manage, 4: Recommend

    while (!exitProgram) {
        // Clear screen and display main menu
        clear();
        WINDOW* menuWin = newwin(height - 3, width, 3, 0);
        box(menuWin, 0, 0);

        std::vector<std::string> menuItems = {
            "1. SEARCH Mode",
            "2. MANAGE Mode",
            "3. RECOMMEND Mode",
            "4. HELP",
            "5. BYE"
        };
        int choice;
        size_t highlight = 0;

        // Enable keypad for menuWin to capture arrow keys
        keypad(menuWin, TRUE);

        while (1) {
            for (size_t i = 0; i < menuItems.size(); ++i) {
                if (i == highlight)
                    wattron(menuWin, A_REVERSE);
                mvwprintw(menuWin, i + 1, 2, "%s", menuItems[i].c_str());
                wattroff(menuWin, A_REVERSE);
            }
            wrefresh(menuWin);

            int c = wgetch(menuWin);
            if (c == KEY_UP) {
                if (highlight == 0)
                    highlight = menuItems.size() - 1;
                else
                    --highlight;
            } else if (c == KEY_DOWN) {
                highlight = (highlight + 1) % menuItems.size();
            } else if (c == 10) { // Enter key
                choice = highlight;
                break;
            }
        }

        // Handle menu selection
        std::string command;
        switch (choice) {
            case 0:
                command = "SEARCH";
                mode = 2;
                break;
            case 1:
                command = "MANAGE";
                mode = 3;
                break;
            case 2:
                command = "RECOMMEND";
                mode = 4;
                break;
            case 3:
                command = "HELP";
                break;
            case 4:
                command = "BYE";
                exitProgram = true;
                break;
            default:
                break;
        }

        // Send command to server
        if (!command.empty()) {
            if (SSL_write(ssl, command.c_str(), command.size()) <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }

            int numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
            if (numbytes <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }
            buf[numbytes] = '\0';
            std::string serverResponse(buf);

            // Display server response
            mvwprintw(menuWin, menuItems.size() + 2, 2, "Server: %s", serverResponse.c_str());
            wrefresh(menuWin);
            wgetch(menuWin);
        }

        delwin(menuWin);

        // If the user selected "BYE", exit the loop
        if (exitProgram) {
            break;
        }

        // Mode-specific interactions
        while (mode != 0 && !exitProgram) {
            clear();
            WINDOW* modeWin = newwin(height - 3, width, 3, 0);
            box(modeWin, 0, 0);

            std::vector<std::string> modeItems;
            if (mode == 2) { // SEARCH Mode
                modeItems = {
                    "1. FIND <book_title>",
                    "2. DETAILS <book_title>",
                    "3. Switch to MANAGE Mode",
                    "4. Switch to RECOMMEND Mode",
                    "5. HELP",
                    "6. Back to Main Menu",
                    "7. BYE"
                };
            } else if (mode == 3) { // MANAGE Mode
                modeItems = {
                    "1. LIST",
                    "2. CHECKOUT <book_title>",
                    "3. RETURN <book_title>",
                    "4. Switch to SEARCH Mode",
                    "5. Switch to RECOMMEND Mode",
                    "6. HELP",
                    "7. Back to Main Menu",
                    "8. BYE"
                };
            } else if (mode == 4) { // RECOMMEND Mode
                modeItems = {
                    "1. GET <book_genre>",
                    "2. RATE <book_title> <rating>",
                    "3. Switch to SEARCH Mode",
                    "4. Switch to MANAGE Mode",
                    "5. HELP",
                    "6. Back to Main Menu",
                    "7. BYE"
                };
            }

            size_t highlight = 0;

            // Enable keypad for modeWin to capture arrow keys
            keypad(modeWin, TRUE);

            while (1) {
                for (size_t i = 0; i < modeItems.size(); ++i) {
                    if (i == highlight)
                        wattron(modeWin, A_REVERSE);
                    mvwprintw(modeWin, i + 1, 2, "%s", modeItems[i].c_str());
                    wattroff(modeWin, A_REVERSE);
                }
                wrefresh(modeWin);

                int c = wgetch(modeWin);
                if (c == KEY_UP) {
                    if (highlight == 0)
                        highlight = modeItems.size() - 1;
                    else
                        --highlight;
                } else if (c == KEY_DOWN) {
                    highlight = (highlight + 1) % modeItems.size();
                } else if (c == 10) { // Enter key
                    choice = highlight;
                    break;
                }
            }

            // Handle mode-specific commands
            std::string userCommand;
            if (mode == 2) { // SEARCH Mode
                switch (choice) {
                    case 0: { // FIND <book_title>
                        mvwprintw(modeWin, modeItems.size() + 2, 2, "Enter book title or author: ");
                        echo();
                        char searchTerm[100];
                        wgetnstr(modeWin, searchTerm, sizeof(searchTerm) - 1);
                        noecho();
                        userCommand = "FIND " + std::string(searchTerm);
                        break;
                    }
                    case 1: { // DETAILS <book_title>
                        mvwprintw(modeWin, modeItems.size() + 2, 2, "Enter book title: ");
                        echo();
                        char bookTitle[100];
                        wgetnstr(modeWin, bookTitle, sizeof(bookTitle) - 1);
                        noecho();
                        userCommand = "DETAILS " + std::string(bookTitle);
                        break;
                    }
                    case 2:
                        userCommand = "MANAGE";
                        mode = 3;
                        break;
                    case 3:
                        userCommand = "RECOMMEND";
                        mode = 4;
                        break;
                    case 4:
                        userCommand = "HELP";
                        break;
                    case 5:
                        userCommand = "MAINMENU"; // Send MAINMENU command
                        mode = 0; // Back to main menu
                        break;
                    case 6:
                        userCommand = "BYE";
                        exitProgram = true;
                        break;
                    default:
                        break;
                }
            } else if (mode == 3) { // MANAGE Mode
                switch (choice) {
                    case 0:
                        userCommand = "LIST";
                        break;
                    case 1: { // CHECKOUT <book_title>
                        mvwprintw(modeWin, modeItems.size() + 2, 2, "Enter book title: ");
                        echo();
                        char bookTitle[100];
                        wgetnstr(modeWin, bookTitle, sizeof(bookTitle) - 1);
                        noecho();
                        userCommand = "CHECKOUT " + std::string(bookTitle);
                        break;
                    }
                    case 2: { // RETURN <book_title>
                        mvwprintw(modeWin, modeItems.size() + 2, 2, "Enter book title: ");
                        echo();
                        char bookTitle[100];
                        wgetnstr(modeWin, bookTitle, sizeof(bookTitle) - 1);
                        noecho();
                        userCommand = "RETURN " + std::string(bookTitle);
                        break;
                    }
                    case 3:
                        userCommand = "SEARCH";
                        mode = 2;
                        break;
                    case 4:
                        userCommand = "RECOMMEND";
                        mode = 4;
                        break;
                    case 5:
                        userCommand = "HELP";
                        break;
                    case 6:
                        userCommand = "MAINMENU"; // Send MAINMENU command
                        mode = 0; // Back to main menu
                        break;
                    case 7:
                        userCommand = "BYE";
                        exitProgram = true;
                        break;
                    default:
                        break;
                }
            } else if (mode == 4) { // RECOMMEND Mode
                switch (choice) {
                    case 0: { // GET <book_genre>
                        mvwprintw(modeWin, modeItems.size() + 2, 2, "Enter genre: ");
                        echo();
                        char genre[100];
                        wgetnstr(modeWin, genre, sizeof(genre) - 1);
                        noecho();
                        userCommand = "GET " + std::string(genre);
                        break;
                    }
                    case 1: { // RATE <book_title> <rating>
                        mvwprintw(modeWin, modeItems.size() + 2, 2, "Enter book title: ");
                        echo();
                        char bookTitle[100];
                        wgetnstr(modeWin, bookTitle, sizeof(bookTitle) - 1);
                        noecho();

                        mvwprintw(modeWin, modeItems.size() + 3, 2, "Enter rating (1-5): ");
                        echo();
                        char rating[10];
                        wgetnstr(modeWin, rating, sizeof(rating) - 1);
                        noecho();

                        userCommand = "RATE " + std::string(bookTitle) + " " + std::string(rating);
                        break;
                    }
                    case 2:
                        userCommand = "SEARCH";
                        mode = 2;
                        break;
                    case 3:
                        userCommand = "MANAGE";
                        mode = 3;
                        break;
                    case 4:
                        userCommand = "HELP";
                        break;
                    case 5:
                        userCommand = "MAINMENU"; // Send MAINMENU command
                        mode = 0; // Back to main menu
                        break;
                    case 6:
                        userCommand = "BYE";
                        exitProgram = true;
                        break;
                    default:
                        break;
                }
            }

            // Send userCommand to server
            if (!userCommand.empty()) {
                if (SSL_write(ssl, userCommand.c_str(), userCommand.size()) <= 0) {
                    ERR_print_errors_fp(stderr);
                    break;
                }

                int numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
                if (numbytes <= 0) {
                    ERR_print_errors_fp(stderr);
                    break;
                }
                buf[numbytes] = '\0';
                std::string serverResponse(buf);

                // Display server response
                mvwprintw(modeWin, modeItems.size() + 5, 2, "Server Response:\n%s", serverResponse.c_str());
                wrefresh(modeWin);
                wgetch(modeWin);
            }

            if (exitProgram || mode == 0) {
                delwin(modeWin);
                break; // Exit the mode-specific loop and return to the main menu loop
            }

            delwin(modeWin);
        }

    }

    // Clean up before exiting the application
    delwin(connWin);
    endwin();

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
