## Compilation
To compile the server and client programs, use the following command:

make

or

g++ -std=c++11 -Wall -pthread server.cpp -o server

g++ -std=c++11 -Wall -pthread client.cpp -o client

#initiate server first

./server server.conf

#initiate client(s) to connect to server

./client client.conf

# Clear executables

make clean

or

rm server
rm client
