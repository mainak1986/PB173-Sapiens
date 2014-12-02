CXX=g++
RM=rm
SRC= client.cpp main.cpp UserIf.cpp encryptor.cpp aes.c
TEST_SRC= client.cpp main.cpp UserIf.cpp
SRCTEST= client.cpp client_test.cpp UserIf.cpp encryptor.cpp aes.c
LIBS=-lssl -lcrypto -lgmp -lpthread
FLAGS= -Wall -Wextra
all: client test

client: client.h $(SRC)
	$(CXX) $(FLAGS) $(SRC) $(LIBS) -o $@
clean:
	$(RM) -f client tClient
test: 
	$(CXX) $(SRCTEST) $(LIBS) -o tClient

test_client: client.h $(TEST_SRC)
	$(CXX) $(TEST_SRC) $(LIBS) -o $@
