/*
 * P1 HELPER
 * ---------
 * Author: Thoshitha Gamage
 * Date: 09/10/2024
 * License: MIT License
 * Description: This helper function loads book data from a .db file into a vector of Book structures.
 *              This code is intended to be used as a helper function in CS447 Fall 2024 P1 server code.
*/

#include <fstream>
#include <sstream>
#include <vector>
#include <string>

struct Book {
    std::string title;
    std::string author;
    std::string genre;
    bool available; // true if available for checkout, false otherwise
    int rating; // 1-5 stars, 0 if not yet rated
};

std::vector<Book> loadBooksFromFile(const std::string& filename) {
    std::vector<Book> books;
    std::ifstream file(filename);
    std::string line;

    // Skip header line
    std::getline(file, line); 

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string title, author, genre, available_str, rating_str;

        std::getline(ss, title, ';');
        std::getline(ss, author, ';');
        std::getline(ss, genre, ';');
        std::getline(ss, available_str, ';');
        std::getline(ss, rating_str, ';');

        Book book;
        book.title = title;
        book.author = author;
        book.genre = genre; 
        book.available = (available_str == "true");
        book.rating = std::stoi(rating_str);

        books.push_back(book);
    }

    return books;
}
