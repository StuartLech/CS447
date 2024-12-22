CXX = g++
CXXFLAGS = -std=c++11 -Wall

SERVER_TARGET = server
CLIENT_TARGET = client

all: $(SERVER_TARGET) $(CLIENT_TARGET)

$(SERVER_TARGET): server.o
	$(CXX) $(CXXFLAGS) -o $(SERVER_TARGET) server.o

$(CLIENT_TARGET): client.o
	$(CXX) $(CXXFLAGS) -o $(CLIENT_TARGET) client.o

server.o: server.cpp p1_helper.cpp
	$(CXX) $(CXXFLAGS) -c server.cpp

client.o: client.cpp
	$(CXX) $(CXXFLAGS) -c client.cpp

clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET) *.o
