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
#include "p1_helper.cpp"  

#define BACKLOG 10  // Number of pending connections in the connection queue
#define MAXDATASIZE 100  // Maximum size of the data buffer for messages

// Signal handler for cleaning up child processes after they terminate
void sigchld_handler(int s) 
{
    (void)s;  // Ignore unused parameter warning
    int saved_errno = errno;  // Save errno for restoration after waitpid

    // Reap all child processes that have exited
    while (waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;  // Restore errno
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

// Function to convert a string to camel case format
std::string toCamelCase(const std::string& input) 
{
    std::string output;
    bool capitalize = true;

    // Iterate through characters and capitalize accordingly
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

// Log the IP address of a connected client with a timestamp
void logConnection(const std::string& clientIP) 
{
    time_t now = time(nullptr);  // Get current time
    tm* localTime = localtime(&now);  // Convert to local time
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);  // Format the timestamp
    std::cout << "[" << timestamp << "] Connection from: " << clientIP << std::endl;
}

// Log the IP address of a disconnected client with a timestamp
void logDisconnection(const std::string& clientIP) 
{
    time_t now = time(nullptr);  // Get current time
    tm* localTime = localtime(&now);  // Convert to local time
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);  // Format the timestamp
    std::cout << "[" << timestamp << "] Client disconnected: " << clientIP << std::endl;
}

// Function to convert a string to lowercase
std::string lowercaseString(const std::string& inputStr) 
{
    std::string resultStr;
    auto it = inputStr.begin();
    while (it != inputStr.end()) {
        char currentChar = *it;
        switch (std::isalpha(currentChar)) {
            case 1:
                resultStr.push_back(std::tolower(currentChar));
                break;
            default:
                resultStr.push_back(currentChar);
                break;
        }
        ++it;
    }
    return resultStr;
}

// Tokenizes a string using a delimiter and returns the tokens as a vector
std::vector<std::string> tokenizeString(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> tokens;
    std::string::size_type start = 0, end;
    size_t delimiterLength = delimiter.length();
    while ((end = str.find(delimiter, start)) != std::string::npos) {
        if (end != start) { 
            tokens.emplace_back(str, start, end - start);
        }
        start = end + delimiterLength;
    }
    if (start < str.length()) {
        tokens.emplace_back(str, start);
    }
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
    for (size_t i = 0; i < books.size(); ++i) {
        const Book& currentBook = books.at(i);  
        file << currentBook.title << ";" << currentBook.author << ";" << currentBook.genre << ";" << (currentBook.available ? "true" : "false") << ";" << currentBook.rating << "\n";  
    }
    file.close(); 
}

// Converts a book to a string representation for easier output
std::string bookToString(const Book& book) {
    std::ostringstream outputStream;
    outputStream << "Title: " << book.title << ", Author: " << book.author << ", Genre: " << book.genre << ", Available: " << (book.available ? "Yes" : "No") << ", Rating: " << book.rating << '\n';  
    return outputStream.str();  
}

// Matches books by a search term in title or author
std::string matchBooks(const std::vector<Book>& books, std::string searchTerm) {
    std::ostringstream outputStream;
    searchTerm = lowercaseString(searchTerm);  
    for (size_t index = 0; index < books.size(); ++index) {
        const Book& currentBook = books.at(index);
        std::string titleLower = lowercaseString(currentBook.title);
        std::string authorLower = lowercaseString(currentBook.author);
        if (titleLower.find(searchTerm) != std::string::npos || authorLower.find(searchTerm) != std::string::npos) {
            outputStream << "ID: " << index + 1 << ", " << bookToString(currentBook);
        }
    }
    return outputStream.str();
}

// Fetch a book's details by its ID
std::string fetchBookByID(const std::vector<Book>& books, int bookID) {
    std::ostringstream outputStream;
    if (bookID > 0 && static_cast<size_t>(bookID) <= books.size()) {
        const Book& selectedBook = books.at(static_cast<size_t>(bookID - 1));
        outputStream << "ID: " << bookID << ", " << bookToString(selectedBook);
    }
    return outputStream.str();
}

// Handles the book checkout process by changing availability status
int handleBookCheckout(std::vector<Book>& books, int bookID) {
    if (bookID > 0 && static_cast<size_t>(bookID) <= books.size()) {
        Book& selectedBook = books.at(static_cast<size_t>(bookID - 1));
        if (selectedBook.available) {
            selectedBook.available = false;  
            return 0; // Success
        } else {
            return 1;  // Book is already checked out
        }
    }
    return 2;  // Book not found
}

// Handles the book return process by updating availability
int handleReturn(std::vector<Book>& books, int bookID) {
    if (bookID > 0 && static_cast<size_t>(bookID) <= books.size()) {
        Book& selectedBook = books.at(static_cast<size_t>(bookID - 1));
        if (!selectedBook.available) {
            selectedBook.available = true; 
            return 0;  // Success
        } else {
            return 1;  // Book was already returned
        }
    }
    return 2;  // Book not found
}

// Lists all available books
std::string listHandler(const std::vector<Book>& books) {
    std::ostringstream outputStream;
    for (size_t index = 0; index < books.size(); ++index) {
        const Book& currentBook = books.at(index);
        if (currentBook.available) {
            outputStream << "ID: " << index + 1 << ", " << bookToString(currentBook);
        }
    }
    return outputStream.str();  
}

// Returns a list of books in a specified genre
std::string getGenre(const std::vector<Book>& books, std::string searchTerm) {
    std::ostringstream outputStream;
    searchTerm = lowercaseString(searchTerm);  
    for (size_t index = 0; index < books.size(); ++index) {
        const Book& currentBook = books.at(index);
        if (lowercaseString(currentBook.genre).find(searchTerm) != std::string::npos) {
            outputStream << "ID: " << index + 1 << ", " << bookToString(currentBook);
        }
    }
    return outputStream.str();  
}

// Modifies the rating of a book by ID
int modifyRating(std::vector<Book>& books, int bookID, int rating) {
    if (rating < 1 || rating > 5) {
        return 2; // Invalid rating
    }
    if (bookID > 0 && static_cast<size_t>(bookID) <= books.size()) {
        Book& selectedBook = books.at(static_cast<size_t>(bookID - 1));
        selectedBook.rating = rating;
        return 0; // Success
    }
    return 1;  // Book not found
}

// Main function - Sets up the server, handles client connections, and processes client requests
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

            char buf[MAXDATASIZE];  // Buffer for storing received data
            int numbytes;  // Number of bytes received

            int modeselect = 0;  // Mode select variable
            bool heloReceived = false;  // HELO command received flag

            // Process incoming client messages
            while (true) 
            { 
                // Receive data from the client
                if ((numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0)) == -1) { 
                    perror("recv"); 
                    exit(1); 
                } else if (numbytes == 0) { // Client disconnected
                    logDisconnection(s); 
                    break; 
                } 

                buf[numbytes] = '\0';  // Null-terminate the received data

                // Load the book database from the file
                std::vector<Book> books = loadBooksFromFile(fileName);
                std::string receivedData(buf);  // Store received data as a string
                std::vector<std::string> parsedMessage = tokenizeString(receivedData, " ");  // Tokenize the received message
                std::string responseData;  // Response to be sent back to the client

                // Check for BYE command to close connection
                if (parsedMessage.size() == 1 && parsedMessage.at(0) == "BYE") {
                    responseData = "200 BYE";
                    if (send(new_fd, responseData.c_str(), responseData.size(), 0) == -1) {
                        perror("send");
                    }
                    close(new_fd);
                    break;
                }
                if (!heloReceived) {  // If HELO hasn't been received yet
                    if (parsedMessage.size() == 2 && parsedMessage.at(0) == "HELO") {
                        std::string clientHost = parsedMessage.at(1);
                        if (clientHost == serverHostname || clientHost == serverIP) {
                            responseData = "200 HELO " + std::string(s) + " (TCP)";
                            heloReceived = true;  // Mark HELO as received
                        } else {
                            responseData = "400 BAD REQUEST - Invalid hostname. Must match server hostname or IP.";
                        }
                    } else {
                        responseData = "400 BAD REQUEST type 'HELO <hostname>' to connect to server";
                    }
                } else {  // Process other client commands
                    if (parsedMessage.size() == 1 && parsedMessage.at(0) == "HELP") {
                        responseData = "200 Available commands: SEARCH, FIND <search term>, DETAILS <book id>, MANAGE, CHECKOUT <book_id>, RETURN <book id>, RECOMMEND, GET <book genre>, RATE <book_id> <rating>, BYE";
                    } else if (parsedMessage.size() == 1 && parsedMessage.at(0) == "BYE") {
                        responseData = "200 Goodbye";
                        if (send(new_fd, responseData.c_str(), responseData.size(), 0) == -1) {
                            perror("send");
                        }
                        close(new_fd);
                        break;
                    }
                    else if (parsedMessage.size() == 1 && parsedMessage.at(0) == "SEARCH") {
                        responseData = "210 Switched to Search Mode";
                        modeselect = 2;
                    } else if (parsedMessage.size() == 1 && parsedMessage.at(0) == "MANAGE") {
                        responseData = "220 Switched to Manage Mode";
                        modeselect = 3;
                    } else if (parsedMessage.size() == 1 && parsedMessage.at(0) == "RECOMMEND") {
                        responseData = "230 Switched to Recommend Mode";
                        modeselect = 4;
                    } else {
                        // Based on the current mode, handle different commands
                        switch (modeselect) {
                            case 2: {  // Search mode
                                if (parsedMessage.size() >= 2 && parsedMessage.at(0) == "FIND") {
                                    std::string searchTerm = receivedData.substr(5);
                                    std::string foundBooks = matchBooks(books, searchTerm);
                                    responseData = foundBooks.empty() ? "304 NO CONTENT" : "250 <data> list of books:\n" + foundBooks;
                                } else if (parsedMessage.size() == 2 && parsedMessage.at(0) == "DETAILS") {
                                    long id = std::stol(parsedMessage.at(1));
                                    std::string bookDetails = fetchBookByID(books, id);
                                    responseData = bookDetails.empty() ? "404 NOT FOUND" : "250 <data> book details:\n" + bookDetails;
                                } else {
                                    responseData = "400 BAD REQUEST";
                                }
                                break;
                            }
                            case 3: {  // Manage mode
                                if (parsedMessage.size() == 1 && parsedMessage.at(0) == "LIST") {
                                    std::string availableBooks = listHandler(books);
                                    responseData = availableBooks.empty() ? "304 NO CONTENT" : "250 <data> list of available books:\n" + availableBooks;
                                } else if (parsedMessage.size() == 2 && parsedMessage.at(0) == "CHECKOUT") {
                                    long id = std::stol(parsedMessage.at(1));
                                    int checkoutStatus = handleBookCheckout(books, id);
                                    responseData = checkoutStatus == 0 ? "250 <data> Book checked out" : (checkoutStatus == 1 ? "403 FORBIDDEN" : "404 NOT FOUND");
                                    syncBookDatabase(books, fileName);  // Sync the book database after checkout
                                } else if (parsedMessage.size() == 2 && parsedMessage.at(0) == "RETURN") {
                                    long id = std::stol(parsedMessage.at(1));
                                    int returnStatus = handleReturn(books, id);
                                    responseData = returnStatus == 0 ? "250 <data> Book returned" : (returnStatus == 1 ? "403 FORBIDDEN" : "404 NOT FOUND");
                                    syncBookDatabase(books, fileName);  // Sync the book database after return
                                } else {
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
                                } else if (parsedMessage.size() == 3 && parsedMessage.at(0) == "RATE") {
                                    long id = std::stol(parsedMessage.at(1));
                                    int rating = std::stoi(parsedMessage.at(2));
                                    int rateStatus = modifyRating(books, id, rating);
                                    responseData = rateStatus == 0 ? "250 <data> Book rating updated" : (rateStatus == 1 ? "404 NOT FOUND" : "403 FORBIDDEN");
                                    syncBookDatabase(books, fileName);  // Sync the book database after rating
                                } else {
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
                if (send(new_fd, responseData.c_str(), responseData.size(), 0) == -1) {
                    perror("send");
                }

            }

            close(new_fd);  // Close the connection with the client
            exit(0);  // Exit child process after handling client
        }
        close(new_fd);  // Close the new socket in the parent process
    }
    
    return 0;
}
