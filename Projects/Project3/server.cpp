// server.cpp

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
#include <vector>
#include <sstream>
#include <ctime>
#include <iomanip>     
#include <tuple>       
#include <sys/stat.h>  
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h> 
#include <openssl/aes.h> 
#include <openssl/bio.h> 
#include <openssl/buffer.h> 
#include "p1_helper.cpp"  

#define BACKLOG 10       
#define MAXDATASIZE 1024 

#define DEBUG_MODE 1  // Set to 0 to disable debug prints

const std::string PRE_SHARED_KEY = "F24447TG"; // Pre-shared key for encryption

// Signal handler for cleaning up child processes after they terminate
void sigchld_handler(int s)
{
    (void)s; // Ignore unused parameter warning
    int saved_errno = errno; // Save errno for restoration after waitpid

    // Reap all child processes that have exited
    while (waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno; // Restore errno
}

// Helper function to get the socket address (IPv4 or IPv6) for later use
void* get_in_addr(struct sockaddr* sa)
{
    // Return the IPv4 address
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    // Otherwise, return the IPv6 address
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Function to log the IP address of a connected client with a timestamp
void logConnection(const std::string& clientIP)
{
    time_t now = time(nullptr); // Get current time
    tm* localTime = localtime(&now); // Convert to local time
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime); // Format the timestamp
    std::cout << "[" << timestamp << "] Connection from: " << clientIP << std::endl;
}

// Function to log the IP address of a disconnected client with a timestamp
void logDisconnection(const std::string& clientIP)
{
    time_t now = time(nullptr); // Get current time
    tm* localTime = localtime(&now); // Convert to local time
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime); // Format the timestamp
    std::cout << "[" << timestamp << "] Client disconnected: " << clientIP << std::endl;
}

// Function to convert a string to lowercase
std::string lowercaseString(const std::string& inputStr)
{
    std::string resultStr = inputStr;
    std::transform(resultStr.begin(), resultStr.end(), resultStr.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return resultStr;
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

// Syncs the book database to a file after modifications
void syncBookDatabase(const std::vector<Book>& books, const std::string& fileName) {
    std::ofstream file(fileName, std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << fileName << std::endl;
        return;
    }
    file << "title;author;genre;available;rating\n";
    for (const auto& currentBook : books) {
        file << currentBook.title << ";" << currentBook.author << ";" << currentBook.genre << ";" 
             << (currentBook.available ? "true" : "false") << ";" << currentBook.rating << "\n";
    }
    file.close();
}

// Converts a book to a string representation for easier output
std::string bookToString(const Book& book) {
    std::ostringstream outputStream;
    outputStream << "Title: " << book.title << ", Author: " << book.author 
                << ", Genre: " << book.genre << ", Available: " 
                << (book.available ? "Yes" : "No") << ", Rating: " << book.rating << '\n';
    return outputStream.str();
}

// Matches books by a search term in title or author
std::string matchBooks(const std::vector<Book>& books, const std::string& searchTerm) {
    std::ostringstream outputStream;
    std::string lowerSearchTerm = lowercaseString(searchTerm);
    for (const auto& currentBook : books) {
        std::string titleLower = lowercaseString(currentBook.title);
        std::string authorLower = lowercaseString(currentBook.author);
        if (titleLower.find(lowerSearchTerm) != std::string::npos || 
            authorLower.find(lowerSearchTerm) != std::string::npos) {
            outputStream << bookToString(currentBook);
        }
    }
    return outputStream.str();
}

// Fetch a book's details by a search term
std::string fetchBookBySearchTerm(const std::vector<Book>& books, const std::string& searchTerm) {
    std::ostringstream outputStream;
    std::string lowerSearchTerm = lowercaseString(searchTerm);
    for (const auto& book : books) {
        std::string titleLower = lowercaseString(book.title);
        std::string authorLower = lowercaseString(book.author);
        if (titleLower.find(lowerSearchTerm) != std::string::npos || 
            authorLower.find(lowerSearchTerm) != std::string::npos) {
            outputStream << bookToString(book);
            return outputStream.str(); // Return details of the first matching book
        }
    }
    return ""; // No matching book found
}

// Handles the book checkout process by changing availability status
int handleBookCheckout(std::vector<Book>& books, const std::string& searchTerm) {
    std::string lowerSearchTerm = lowercaseString(searchTerm);
    for (auto& book : books) {
        std::string titleLower = lowercaseString(book.title);
        std::string authorLower = lowercaseString(book.author);
        if (titleLower.find(lowerSearchTerm) != std::string::npos || 
            authorLower.find(lowerSearchTerm) != std::string::npos) {
            if (book.available) {
                book.available = false;
                return 0; // Success
            } else {
                return 1;  // Book is already checked out
            }
        }
    }
    return 2;  // Book not found
}

// Handles the book return process by updating availability
int handleReturn(std::vector<Book>& books, const std::string& searchTerm) {
    std::string lowerSearchTerm = lowercaseString(searchTerm);
    for (auto& book : books) {
        std::string titleLower = lowercaseString(book.title);
        std::string authorLower = lowercaseString(book.author);
        if (titleLower.find(lowerSearchTerm) != std::string::npos || 
            authorLower.find(lowerSearchTerm) != std::string::npos) {
            if (!book.available) {
                book.available = true;
                return 0;  // Success
            } else {
                return 1;  // Book was already returned
            }
        }
    }
    return 2;  // Book not found
}

// Lists all available books
std::string listHandler(const std::vector<Book>& books) {
    std::ostringstream outputStream;
    for (const auto& currentBook : books) {
        if (currentBook.available) {
            outputStream << bookToString(currentBook);
        }
    }
    return outputStream.str();
}

// Returns a list of books in a specified genre
std::string getGenre(const std::vector<Book>& books, const std::string& searchTerm) {
    std::ostringstream outputStream;
    std::string lowerSearchTerm = lowercaseString(searchTerm);
    for (const auto& currentBook : books) {
        if (lowercaseString(currentBook.genre).find(lowerSearchTerm) != std::string::npos) {
            outputStream << bookToString(currentBook);
        }
    }
    return outputStream.str();
}

// Modifies the rating of a book by search term
int modifyRating(std::vector<Book>& books, const std::string& searchTerm, int rating) {
    if (rating < 1 || rating > 5) {
        return 2; // Invalid rating
    }
    std::string lowerSearchTerm = lowercaseString(searchTerm);
    for (auto& book : books) {
        std::string titleLower = lowercaseString(book.title);
        std::string authorLower = lowercaseString(book.author);
        if (titleLower.find(lowerSearchTerm) != std::string::npos || 
            authorLower.find(lowerSearchTerm) != std::string::npos) {
            book.rating = rating;
            return 0; // Success
        }
    }
    return 1;  // Book not found
}

// Generate a random password of 5 characters meeting the complexity requirements
std::string generatePassword() {
    const std::string uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string numbers = "0123456789";
    const std::string symbols = "!@#$%&*";
    const std::string allChars = uppercaseLetters + numbers + symbols + "abcdefghijklmnopqrstuvwxyz";

    std::string password;
    bool hasUppercase = false, hasNumber = false, hasSymbol = false;

    while (true) {
        unsigned char randomBytes[5];
        if (!RAND_bytes(randomBytes, sizeof(randomBytes))) {
            std::cerr << "Error generating random bytes for password" << std::endl;
            exit(1);
        }

        password.clear();
        hasUppercase = hasNumber = hasSymbol = false;

        for (int i = 0; i < 5; ++i) {
            char c = allChars[randomBytes[i] % allChars.length()];
            if (uppercaseLetters.find(c) != std::string::npos) hasUppercase = true;
            if (numbers.find(c) != std::string::npos) hasNumber = true;
            if (symbols.find(c) != std::string::npos) hasSymbol = true;
            password += c;
        }

        if (hasUppercase && hasNumber && hasSymbol && symbols.find(password[0]) == std::string::npos) {
            break; // Password meets the complexity requirements
        }
    }

    return password;
}

// Generate a random salt of 6 printable characters excluding whitespace
std::string generateSalt() {
    const std::string printableChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%&*()_+-=[]{}|;':\",./<>?";

    std::string salt;
    unsigned char randomBytes[6];
    if (!RAND_bytes(randomBytes, sizeof(randomBytes))) {
        std::cerr << "Error generating random bytes for salt" << std::endl;
        exit(1);
    }

    for (int i = 0; i < 6; ++i) {
        char c = printableChars[randomBytes[i] % printableChars.length()];
        salt += c;
    }

    return salt;
}

// Interleave salt and password
std::string interleaveSaltAndPassword(const std::string& salt, const std::string& password) {
    std::string saltedPassword;
    size_t maxLength = std::max(salt.length(), password.length());
    for (size_t i = 0; i < maxLength; ++i) {
        if (i < salt.length()) saltedPassword += salt[i];
        if (i < password.length()) saltedPassword += password[i];
    }
    return saltedPassword;
}

// Hash the salted password using SHA-512
std::string hashPassword(const std::string& saltedPassword) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        std::cerr << "Error creating EVP_MD_CTX" << std::endl;
        exit(1);
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr)) {
        std::cerr << "Error initializing digest" << std::endl;
        exit(1);
    }

    if (1 != EVP_DigestUpdate(mdctx, saltedPassword.c_str(), saltedPassword.length())) {
        std::cerr << "Error updating digest" << std::endl;
        exit(1);
    }

    unsigned int hashLength;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hashLength)) {
        std::cerr << "Error finalizing digest" << std::endl;
        exit(1);
    }

    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hashLength; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return oss.str();
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

// Load user credentials from .book_shadow file
std::vector<std::tuple<std::string, std::string, std::string>> loadUserCredentials() {
    std::vector<std::tuple<std::string, std::string, std::string>> credentials;
    std::ifstream file(".book_shadow");
    if (!file.is_open()) {
        // File doesn't exist yet, return empty vector
        return credentials;
    }
    std::string line;
    while (std::getline(file, line)) {
        std::vector<std::string> tokens = tokenizeString(line, ":");
        if (tokens.size() == 3) {
            credentials.emplace_back(tokens[0], tokens[1], tokens[2]); // username, salt, hashed password
        }
    }
    file.close();
    return credentials;
}

// Save user credentials to .book_shadow file
void saveUserCredentials(const std::vector<std::tuple<std::string, std::string, std::string>>& credentials) {
    std::ofstream file(".book_shadow", std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open .book_shadow file" << std::endl;
        return;
    }
    for (const auto& entry : credentials) {
        file << std::get<0>(entry) << ":" << std::get<1>(entry) << ":" << std::get<2>(entry) << "\n";
    }
    file.close();
    // Set file permissions to owner read/write only
    chmod(".book_shadow", S_IRUSR | S_IWUSR);
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
    hints.ai_family = AF_UNSPEC;  // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP connection
    hints.ai_flags = AI_PASSIVE;  // Automatically assign the IP address of the host

    char serverHostname[256];
    struct hostent* hostInfo;
    int hostnameResult;
    struct in_addr** ipAddressList;
    hostnameResult = gethostname(serverHostname, sizeof(serverHostname));  // Get the server's hostname

    if (hostnameResult == -1) {
        perror("gethostname error");
        exit(1);
    }
    hostInfo = gethostbyname(serverHostname);  // Resolve the hostname to an IP address
    if (hostInfo == NULL) {
        perror("gethostbyname error");
        exit(1);
    }
    ipAddressList = (struct in_addr**)hostInfo->h_addr_list;
    std::string serverIP = inet_ntoa(*ipAddressList[0]);  // Get the server's IP address

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }

    std::string configFileName = argv[1];  // Get the configuration file from the command line

    std::string port;
    std::ifstream configFile(configFileName);
    if (!configFile.is_open()) {
        std::cerr << "Error opening configuration file: " << configFileName << std::endl;
        return 1;
    }

    // Read the port number from the configuration file
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

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the TLS version to TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Load server's certificate and key
    if (SSL_CTX_use_certificate_file(ctx, "p3server.crt", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading server certificate" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "p3server.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading server private key" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set cipher suites
    if (!SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")) {
        std::cerr << "Error setting cipher suites" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Get address information for server
    if ((rv = getaddrinfo(nullptr, port.c_str(), &hints, &servinfo)) != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    // Loop through all the results and bind to the first we can
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

    freeaddrinfo(servinfo);  // Free the linked list of address information

    if (p == nullptr) {
        std::cerr << "server: failed to bind" << std::endl;
        return 1;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        throw std::system_error(errno, std::generic_category(), "listen");
    }

    // Set up signal handling for child processes
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        throw std::system_error(errno, std::generic_category(), "sigaction");
    }

    std::cout << "server: waiting for connections..." << std::endl;

    std::string fileName = "books.db";  // Book database file

    // Main loop to handle incoming client connections
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

        // Fork a new process to handle the client
        if (!fork()) {
            close(sockfd);  // Close the listening socket in the child process

            // Create SSL structure
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, new_fd);

            // Accept TLS connection
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                close(new_fd);
                exit(EXIT_FAILURE);
            }

            char buf[MAXDATASIZE];  // Buffer for storing received data
            int numbytes;  // Number of bytes received

            int modeselect = 0;  // Mode select variable (0: default, 2: SEARCH, 3: MANAGE, 4: RECOMMEND)
            bool authenticated = false;  // Authentication flag
            std::string username;

            // Process incoming client messages
            while (true)
            {
                // Receive data from the client
                numbytes = SSL_read(ssl, buf, sizeof(buf) - 1);
                if (numbytes <= 0) {
                    ERR_print_errors_fp(stderr);
                    logDisconnection(s);
                    break;
                }

                buf[numbytes] = '\0';  // Null-terminate the received data

                // Load the book database from the file
                std::vector<Book> books = loadBooksFromFile(fileName);
                std::string receivedData(buf);  // Store received data as a string
                std::vector<std::string> parsedMessage = tokenizeString(receivedData, " ");  // Tokenize the received message
                std::string responseData;  // Response to be sent back to the client

                if (!authenticated) {
                    // Handle USER and PASS commands
                    if (parsedMessage.size() == 2 && parsedMessage.at(0) == "USER") {
                        username = parsedMessage.at(1);
                        responseData = "331 Username OK, need password";
                    } else if (parsedMessage.size() >= 2 && parsedMessage.at(0) == "PASS") {
                        // Load user credentials
                        std::vector<std::tuple<std::string, std::string, std::string>> credentials = loadUserCredentials();
                        bool userExists = false;
                        std::string storedSalt, storedHash;
                        for (const auto& entry : credentials) {
                            if (std::get<0>(entry) == username) {
                                userExists = true;
                                storedSalt = std::get<1>(entry);
                                storedHash = std::get<2>(entry);
                                break;
                            }
                        }

                        std::string encryptedPassword = receivedData.substr(5); // Extract encrypted password

                        // **Print the encrypted password received**
                        #if DEBUG_MODE
                        std::ofstream debugLog("server_debug.log", std::ios::app);
                        debugLog << "Encrypted password received: " << encryptedPassword << std::endl;
                        #endif

                        // Decrypt the password using the pre-shared key
                        std::string decryptedPassword = decryptData(encryptedPassword, PRE_SHARED_KEY);

                        // **Print the base64-encoded password after decryption**
                        #if DEBUG_MODE
                        debugLog << "Base64-encoded password after decryption: " << decryptedPassword << std::endl;
                        #endif

                        // Base64 decode the password
                        std::string decodedPassword = base64Decode(decryptedPassword);

                        // **Print the decoded password**
                        #if DEBUG_MODE
                        debugLog << "Decoded password: " << decodedPassword << std::endl;
                        debugLog.close();
                        #endif

                        if (userExists) {
                            // Authenticate user
                            std::string saltedPassword = interleaveSaltAndPassword(storedSalt, decodedPassword);
                            std::string hashedPassword = hashPassword(saltedPassword);
                            if (hashedPassword == storedHash) {
                                authenticated = true;
                                responseData = "230 User logged in, proceed";
                            } else {
                                responseData = "530 Login incorrect";
                            }
                        } else {
                            // New user registration
                            std::string password = generatePassword();
                            std::string salt = generateSalt();
                            std::string saltedPassword = interleaveSaltAndPassword(salt, password);
                            std::string hashedPassword = hashPassword(saltedPassword);

                            // Store new credentials
                            credentials.emplace_back(username, salt, hashedPassword);
                            saveUserCredentials(credentials);

                            // Base64 encode the password
                            std::string base64Password = base64Encode(password);

                            // Encrypt the password to send to the client
                            std::string encryptedPasswordToSend = encryptData(base64Password, PRE_SHARED_KEY);
                            responseData = "New user created. Encrypted password: " + encryptedPasswordToSend + "\nPlease reconnect and login with your new credentials.";
                            SSL_write(ssl, responseData.c_str(), responseData.size());
                            SSL_shutdown(ssl);
                            SSL_free(ssl);
                            close(new_fd);
                            exit(0);
                        }
                    } else {
                        responseData = "530 Please login with USER and PASS";
                    }
                } else {
                    // User is authenticated, process other commands
                    if (parsedMessage.size() == 1 && parsedMessage.at(0) == "HELP") {
                        // Mode-specific HELP responses
                        switch (modeselect) {
                            case 0: // Default mode
                                responseData = "200 Available commands:\n"
                                               "- SEARCH: Switch to Search Mode\n"
                                               "- MANAGE: Switch to Manage Mode\n"
                                               "- RECOMMEND: Switch to Recommend Mode\n"
                                               "- HELP: Display this help message\n"
                                               "- BYE: Disconnect from server";
                                break;
                            case 2: // SEARCH mode
                                responseData = "200 SEARCH Mode Commands:\n"
                                               "- FIND <book_title>: Search for books by title or author\n"
                                               "- DETAILS <book_title>: Get details of a specific book\n"
                                               "- MANAGE: Switch to Manage Mode\n"
                                               "- RECOMMEND: Switch to Recommend Mode\n"
                                               "- HELP: Display this help message\n"
                                               "- BYE: Disconnect from server";
                                break;
                            case 3: // MANAGE mode
                                responseData = "200 MANAGE Mode Commands:\n"
                                               "- LIST: List all available books\n"
                                               "- CHECKOUT <book_title>: Checkout a book\n"
                                               "- RETURN <book_title>: Return a book\n"
                                               "- SEARCH: Switch to Search Mode\n"
                                               "- RECOMMEND: Switch to Recommend Mode\n"
                                               "- HELP: Display this help message\n"
                                               "- BYE: Disconnect from server";
                                break;
                            case 4: // RECOMMEND mode
                                responseData = "200 RECOMMEND Mode Commands:\n"
                                               "- GET <book_genre>: Get book recommendations by genre\n"
                                               "- RATE <book_title> <rating>: Rate a book (1-5)\n"
                                               "- SEARCH: Switch to Search Mode\n"
                                               "- MANAGE: Switch to Manage Mode\n"
                                               "- HELP: Display this help message\n"
                                               "- BYE: Disconnect from server";
                                break;
                            default:
                                responseData = "400 BAD REQUEST";
                                break;
                        }
                    } 
                    else if (parsedMessage.size() == 1 && parsedMessage.at(0) == "BYE") {
                        responseData = "200 Goodbye";
                        SSL_write(ssl, responseData.c_str(), responseData.size());
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        close(new_fd);
                        exit(0);
                    } 
                    else if (parsedMessage.size() == 1 && parsedMessage.at(0) == "SEARCH") {
                        responseData = "210 Switched to Search Mode";
                        modeselect = 2;
                    } 
                    else if (parsedMessage.size() == 1 && parsedMessage.at(0) == "MANAGE") {
                        responseData = "220 Switched to Manage Mode";
                        modeselect = 3;
                    } 
                    else if (parsedMessage.size() == 1 && parsedMessage.at(0) == "RECOMMEND") {
                        responseData = "230 Switched to Recommend Mode";
                        modeselect = 4;
                    } 
                    // Handle "MAINMENU" Command
                    else if (parsedMessage.size() == 1 && parsedMessage.at(0) == "MAINMENU") {
                        modeselect = 0; // Reset to Main Menu mode
                        responseData = "200 Switched to Main Menu";
                    }
                    else {
                        // Based on the current mode, handle different commands
                        switch (modeselect) {
                            case 2: {  // Search mode
                                if (parsedMessage.size() >= 2 && parsedMessage.at(0) == "FIND") {
                                    std::string searchTerm = receivedData.substr(5);
                                    std::string foundBooks = matchBooks(books, searchTerm);
                                    responseData = foundBooks.empty() ? "304 NO CONTENT" : "250 <data> list of books:\n" + foundBooks;
                                } 
                                else if (parsedMessage.size() >= 2 && parsedMessage.at(0) == "DETAILS") {
                                    std::string searchTerm = receivedData.substr(8); // Extract search term after "DETAILS "
                                    std::string bookDetails = fetchBookBySearchTerm(books, searchTerm);
                                    responseData = bookDetails.empty() ? "404 NOT FOUND" : "250 <data> book details:\n" + bookDetails;
                                } 
                                else {
                                    responseData = "400 BAD REQUEST";
                                }
                                break;
                            }
                            case 3: {  // Manage mode
                                if (parsedMessage.size() == 1 && parsedMessage.at(0) == "LIST") {
                                    std::string availableBooks = listHandler(books);
                                    responseData = availableBooks.empty() ? "304 NO CONTENT" : "250 <data> list of available books:\n" + availableBooks;
                                } 
                                else if (parsedMessage.size() >= 2 && parsedMessage.at(0) == "CHECKOUT") {
                                    std::string searchTerm = receivedData.substr(9); // Extract search term after "CHECKOUT "
                                    int checkoutStatus = handleBookCheckout(books, searchTerm);
                                    if (checkoutStatus == 0) {
                                        responseData = "250 <data> Book checked out";
                                        syncBookDatabase(books, fileName);  // Sync the book database after checkout
                                    } 
                                    else if (checkoutStatus == 1) {
                                        responseData = "403 FORBIDDEN - Book is already checked out";
                                    } 
                                    else {
                                        responseData = "404 NOT FOUND - Book not found";
                                    }
                                } 
                                else if (parsedMessage.size() >= 2 && parsedMessage.at(0) == "RETURN") {
                                    std::string searchTerm = receivedData.substr(7); // Extract search term after "RETURN "
                                    int returnStatus = handleReturn(books, searchTerm);
                                    if (returnStatus == 0) {
                                        responseData = "250 <data> Book returned";
                                        syncBookDatabase(books, fileName);  // Sync the book database after return
                                    } 
                                    else if (returnStatus == 1) {
                                        responseData = "403 FORBIDDEN - Book was not checked out";
                                    } 
                                    else {
                                        responseData = "404 NOT FOUND - Book not found";
                                    }
                                } 
                                else {
                                    responseData = "400 BAD REQUEST";
                                }
                                break;
                            }
                            case 4: {  // Recommend mode
                                if (parsedMessage.size() >= 2 && parsedMessage.at(0) == "GET") {
                                    std::string genre = receivedData.substr(4);
                                    genre = genre.erase(0, genre.find_first_not_of(" "));
                                    std::string booksInGenre = getGenre(books, genre);
                                    responseData = booksInGenre.empty() ? "304 NO CONTENT" : "250 <data> list of recommendations:\n" + booksInGenre;
                                } 
                                else if (parsedMessage.size() >= 3 && parsedMessage.at(0) == "RATE") {
                                    // Extract rating from the last token
                                    std::string ratingStr = parsedMessage.back();
                                    int rating = 0;
                                    try {
                                        rating = std::stoi(ratingStr);
                                    } catch (const std::invalid_argument& e) {
                                        responseData = "403 FORBIDDEN - Invalid rating";
                                        break;
                                    } catch (const std::out_of_range& e) {
                                        responseData = "403 FORBIDDEN - Rating out of range";
                                        break;
                                    }

                                    // Reconstruct the book title from the tokens between parsedMessage[1] and parsedMessage[parsedMessage.size() - 2]
                                    std::string searchTerm;
                                    for (size_t i = 1; i < parsedMessage.size() - 1; ++i) {
                                        if (i > 1) searchTerm += " ";
                                        searchTerm += parsedMessage[i];
                                    }

                                    int rateStatus = modifyRating(books, searchTerm, rating);
                                    if (rateStatus == 0) {
                                        responseData = "250 <data> Book rating updated";
                                        syncBookDatabase(books, fileName);  // Sync the book database after rating
                                    } 
                                    else if (rateStatus == 1) {
                                        responseData = "404 NOT FOUND - Book not found";
                                    } 
                                    else {
                                        responseData = "403 FORBIDDEN - Invalid rating";
                                    }
                                } 
                                else {
                                    responseData = "400 BAD REQUEST";
                                }
                                break;
                            }
                            default:
                                responseData = "400 BAD REQUEST";
                                break;
                        }
                    }
                }

                // Send the response back to the client
                if (SSL_write(ssl, responseData.c_str(), responseData.size()) <= 0) {
                    ERR_print_errors_fp(stderr);
                    break;
                }
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(new_fd);  // Close the connection with the client
            exit(0);  // Exit child process after handling client
        }
        close(new_fd);  // Close the new socket in the parent process
    }

    // Clean up OpenSSL
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
