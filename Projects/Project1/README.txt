## Compilation
To compile the server and client programs, use the following command:

make

#initiate server first

./server server.conf

#initiate client(s) to connect to server

./client client.conf

HELO <hostname
HELP
SEARCH
FIND <search_term>
DETAILS <book_id>
MANAGE
CHECKOUT <book_id>
RETURN <book_id>
LIST
RECOMMEND
GET <genre>
RATE <book_id> <rating>
BYE

To remove the executables, use the following command:

make clean
