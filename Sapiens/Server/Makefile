CXX=g++
RM=rm
SRC=server.cpp main.cpp ClientList.cpp Connection.cpp
DEPS = server.h ClientList.h packet.h Connection.h common.h
LIBS=-lssl -lcrypto -lpthread -lgmp
CFLAGS=-Wall -Wextra -O2 

all: server

server: $(DEPS) $(SRC)
	$(CXX) $(CFLAGS) $(SRC) $(LIBS) -o $@
clean:
	$(RM) -f server
