#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
#include<sys/stat.h>

#include "server.h"




TEST_CASE( "Sending Response to Server", "Server to Client" ) 
{
	//int ret=1;
	SSLServer *server  = new SSLServer();
	REQUIRE((server->LoadCertificates()) == 0);
        REQUIRE((server->Open()) == 0);    /* create server socket */
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server->getSD(), (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        fprintf(stdout,"Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(server->getCTX());              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */

	// Returns 0 on success	
    	REQUIRE((server->Servlet(ssl)) == 0);
	delete server;
}


/*
TEST_CASE( "Opening connection and loading certificate", "Client to server" ) {
        //int ret=1;
        Client * client  = new Client ();
        // Returns 0 on success
        REQUIRE( (client->initSSL()) == 0);
	REQUIRE((client->loadCertificate())==0);
	REQUIRE((client->openConnection())==0);
	unsigned char* response;
	int len;
	client->stopSSL(response, &len);
	free(response);
        delete client;

}

TEST_CASE( "SSL handshake", "Client to server" ) {
        int ret=1;
	unsigned char* response;
	int len;
        Client * client  = new Client ();
      
        REQUIRE( (client->initSSL()) == 0);
        REQUIRE((client->loadCertificate())==0);
        REQUIRE((client->openConnection())==0);
	REQUIRE(client->startSSL(response, &len)==0);
	REQUIRE(response[1]==2);
	free(response);

	REQUIRE((client->stopSSL(response, &len))==0);
        free(response);

        delete client;
}                                   


TEST_CASE( "Reigster to server", "Client to server" ) {
        int ret=1;
        unsigned char* response;
        int len;
        Client * client  = new Client ();
        REQUIRE( (client->initSSL()) == 0);
        REQUIRE((client->loadCertificate())==0);
        REQUIRE((client->openConnection())==0);
        REQUIRE((client->startSSL(response, &len))==0);
        REQUIRE(response[1]==2);
        free(response);

	REQUIRE(client->registerToServer(response, &len)==0);
	REQUIRE(response[1]==2);
	
	REQUIRE(client->stopSSL(response, &len)==0);
        free(response);

        delete client;
}
        
*/
         
