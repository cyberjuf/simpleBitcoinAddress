OBJECTS = bitcoin.o applog.o base58.o combination.o hash.o result.o utility.o segwit_addr.o
all : bitcoinaddress
	g++ -o bitcoinaddress $(OBJECTS)  -lcrypto
clean :
	rm bitcoinaddress $(OBJECTS)
bitcoinaddress :  $(OBJECTS)
	g++ -c applog.c base58.c combination.c hash.c result.c utility.c segwit_addr.c bitcoin.cpp
	