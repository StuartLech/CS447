all: server client

server: server.cpp
	g++ -std=c++11 -Wall -pthread server.cpp -o server
client: client.cpp
	g++ -std=c++11 -Wall -pthread client.cpp -o client

clean:
	rm -f server client
