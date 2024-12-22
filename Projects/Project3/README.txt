## Compilation
To compile the server and client programs, use the following command:

make

#initiate server first

./server server.conf

#initiate client(s) to connect to server

./client client.conf

If Makefile Does Not work:

g++ -std=c++17 -Wall -pthread server.cpp -o server -lssl -lcrypto -lncurses

g++ -std=c++17 -Wall -pthread client.cpp -o client -lssl -lcrypto -lncurses

openssl req -x509 -nodes -newkey rsa:4096 -keyout p3server.key -out p3server.crt -days 365


To remove the executables, Key and Cert, use the following command:

make clean

or

rm -f server client p3server.key p3server.crt
