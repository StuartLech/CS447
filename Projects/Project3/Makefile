all: server client cert

server: server.cpp
	g++ -std=c++17 -Wall -pthread server.cpp -o server -lssl -lcrypto -lncurses

client: client.cpp
	g++ -std=c++17 -Wall -pthread client.cpp -o client -lssl -lcrypto -lncurses

cert:
	openssl req -x509 -nodes -newkey rsa:4096 -keyout p3server.key -out p3server.crt -days 365

clean:
	rm -f server client p3server.key p3server.crt server_debug.log client_debug.log
