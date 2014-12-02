#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
#include<sys/stat.h>

#include "client.h"

#define ONE

#ifdef ALL
TEST_CASE( "Opening log file", "Client to server" ) {
	//int ret=1;
	printf("Client %d:TEST:1: Opening log file\n",getid());	
	Client * client  = new Client ();
	// Returns 0 on success	
    	REQUIRE( client->initLog() == 0);
	delete client;
}

TEST_CASE( "Opening connection and loading certificate", "Client to server" ) {
        //int ret=1;
        Client * client  = new Client ();
        // Returns 0 on success
        printf("Client %d:TEST:2: Open connection and load certificate\nTEST:2:initSSL\n",getid());
        REQUIRE( (client->initSSL()) == 0);
	printf("Client %d:TEST:2:loadCertificates\n",getid());
	REQUIRE((client->loadCertificates())==0);
	printf("Client %d:TEST:2:openConnection\n",getid());
	REQUIRE((client->openConnection())==0);

	/*unsigned char* response;
	int len;
	printf("TEST:2:stopSSL\n");
	client->stopSSL(response, &len);
	if(response)free(response);
        delete client;
	*/
	printf("Client %d:TEST:2:COMPLETED\n",getid());
}

TEST_CASE( "SSL handshake", "Client to server" ) {
        int ret=1;
	unsigned char* response;
	int len;
        Client * client  = new Client ();
      
	printf("Client %d:TEST: SSL handshake\n",getid());
        REQUIRE( (client->initSSL()) == 0);
        REQUIRE((client->loadCertificates())==0);
        REQUIRE((client->openConnection())==0);
	REQUIRE(client->startSSL(response, &len)==0);
	REQUIRE(response != NULL);
	REQUIRE(response[1]==2);
	if(response)free(response);
	response = NULL;
	REQUIRE((client->stopSSL(response, &len))==0);
        if(response)free(response);

        delete client;
}                                   
#endif	// ALL

#ifdef ONE
TEST_CASE( "Reigster to server", "Client to server" ) {
        int ret=1;
        unsigned char* response=NULL;
        int len;
        Client * client  = new Client ();
	printf("Client %d:TEST:4: Register to server\n",getid());
        REQUIRE( (client->initSSL()) == 0);
        REQUIRE((client->loadCertificates())==0);
        REQUIRE((client->openConnection())==0);
        REQUIRE((client->startSSL(response, &len))==0);
        REQUIRE(response[1]==2);
	printf("Client %d:TEST:4: Freeing the memory\n ",getid());
        if(response)free(response);
	printf("Client %d:TEST:4: Freed the memory\n ",getid());

	
	REQUIRE(client->registerToServer(response, &len)==0);
	REQUIRE(response[1]==2);
	if(response) free(response);

	
	REQUIRE(client->stopSSL(response, &len)==0);
        if(response)free(response);

        delete client;
}
        
#endif
         
