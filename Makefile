all : clean cleantest sslproxy

sslproxy:: sslproxy.o
	g++ -o sslproxy sslproxy.o -lnetfilter_queue -lssl -lcrypto
sslproxy.o:
	g++ -c -o sslproxy.o nfqnl_test.cpp -std=c++11


test : cleantest client server

client: client.o
	g++ -o client client.o
server: server.o
	g++ -o server server.o
client.o:
	g++ -c -o client.o client.cpp
server.o:
	g++ -c -o server.o server.cpp
clean:
	rm -f *.o
	rm -f sslproxy

cleantest:
	rm -f client
	rm -f server
	rm -f *.o

