##I have most all the functionality but my server implementation is buggy. The server and clients may need to be rerun to properly test all functionality. Check ISSUES in report.
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
