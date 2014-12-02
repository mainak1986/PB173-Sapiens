#ifndef __CLIENTLIST_H
#define __CLIENTLIST_H

#include<time.h>
#include<stdlib.h>
#include<stdio.h>
#include "openssl/ssl.h"
#include <arpa/inet.h>

#include "common.h"

/**
 * This class maintains the list of client
 * It keeps track of client status
 * It maintains list of certificates
 * It maintains the list of socket streams through which client is communicating
 */
class ClientList
{
private:
	enum{SLEEP, ACTIVE, BUSY}; /** Possible States of client */
	long clientIP[MAX_CLIENT_LIST]; /** IP/Unique address of the client */
	short status[MAX_CLIENT_LIST]; /** current status of the client*/
	X509 *certificate[MAX_CLIENT_LIST]; /** Certificate of the client */
	long LastActivity[MAX_CLIENT_LIST]; /** Last activity time stamp */
	SSL* sslList[MAX_CLIENT_LIST]; /** List of the socket streams */
	
	int numClients; /** Number of the clients currently connected */
	int updateStatus(); 
	public:
		ClientList(); /** Constructor for initialization */
		~ClientList(); /** Destructor for releasing the memory allocated to objects */
		void setActive(long clientId) ; /** Mark the recent client activity */
		long getNewID(); /** Get an ID for the new Client */
		long getClientID(long clientIP); /** Get the client ID for the given client IP address */
		char *getClientList(int clientId,int &len); /** Return the list of currently active users */
		X509 *getClientCertificate(int clientID); /** get the client certificate; Assumption that no one will make any changes to certificates */
		SSL *getClientStream(int clientID); /** Get the SSL stream of the given client */
		EVP_PKEY *getClientPublicKey(int clientID); /** Get the public key of the given client */
		int add(long clientIP,X509 *cert,SSL* ssl); /** Add a new client with the given IPaddress, certificate and stream connection */
};

#endif
