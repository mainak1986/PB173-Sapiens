#include "ClientList.h"

/**
 * Client list constructor
 */
ClientList::ClientList() {
	numClients = 1;
}

/**
 * Destructor of client list
 * Free all the users certificates
 */
ClientList::~ClientList() {
	int i;
	for(i=1;i<numClients;i++)
	{
		if(this->certificate[i]) free(this->certificate[i]);
	}
}

/**
 * Recent activity found by client 
 * set the client as active client 
 */
	void ClientList::setActive(long clientId) 
	{
		if( clientId > this->numClients)
			return;
		this->status[clientId]=ACTIVE;
		LastActivity[clientId]=time(0);
		return;
	}

/**
 * Get a new ID for the Client
 * This method is called during the new client registration
 * for giving the unique client ID
 */
	long ClientList::getNewID() {
		return numClients;
	}

/**
 * get the client ID id having the given client IP from the client list
 */
	long ClientList::getClientID(long clientIP)
	{
		int i;
		for(i=1;i<numClients;i++) {
			//printf("get Client id: %d %d <=> %d\n",i, clientIP, this->clientIP[i]);
			if(this->clientIP[i] == clientIP) {
				//printf("get Client id: %d\n",i);
				return i;
			}
		}
		return 0;
	}

/**
 * get the list of active users
 * clientId gives the ID of the client who is requesting
 * the list of activ users
 * In the list of active users, current user will not be present
 * len is the argument which gives the length of the character array
 * which contains the list of active users 
 */
	char *ClientList::getClientList(int clientId, int &len) {
		int size=sizeof(int);/*2* 1 for id and 1 for \n */
		//int size=sizeof(long) +sizeof(short)/*+2*/; /* 1 for , and 1 for \n */
		char *list = (char *)malloc(numClients*size+4);
		if(list == NULL) {
			printf("No Memory Left\n");
			exit(0);
		}
		memset(list,0,numClients*size+4);
			//printf("getClientList %d\n",clientId);
		updateStatus();
		int j=0;
		for(int i=1;i<numClients;i++) {
			//printf("client %d, status=%d\n",i,status[i]);
			if(status[i] == ACTIVE && i!= clientId) {
				//printf("in to list i=%d,clientId=%d\n",i,clientId);
				//sprintf(list+j*size,"%02d\n",i);
				list[j*size]=(i>>24) & 0xFF;
				list[j*size+1]=(i>>16) & 0xFF;
				list[j*size+2]=(i>>8) & 0xFF;
				list[j*size+3]=(i) & 0xFF;
				j++;
			}
		}
		*(list+j*size)=0;
		len = j*size;
		printf("len = %d, list: %s\n",len, list);
		printf("Client List: ");
		for(int i=0;i<len;i++)
			printf("%x ",list[i]);
		printf("\n");
		return list;
	}

/**
 * get the certificate of the client having the given ID
 */
	X509 *ClientList::getClientCertificate(int clientID)
	{
		if(clientID < numClients)
			return certificate[clientID];
		return 0;
	}

/**
 * get the socket stream of the client whose ID is passed as argument
 */
	SSL *ClientList::getClientStream(int clientID)
	{
		if(clientID < numClients)
		return sslList[clientID];
		return 0;
	}

/**
 * Return the public key of the given client 
 */
	EVP_PKEY *ClientList::getClientPublicKey(int clientID)
	{
		EVP_PKEY *pkey = NULL;
		X509 *cert = getClientCertificate(clientID);
		if(!cert) {
			fprintf(stderr, "Could not find %d clientCertificate\n",clientID);
			return 0;
		}
		/* ---------------------------------------------------------- *
		 * Extract the certificate's public key data.                 *
		 * ---------------------------------------------------------- */
		if ((pkey = X509_get_pubkey(cert)) == NULL) {
		    fprintf(stderr,"Error getting public key from certificate");
			return 0;
		}

		/* ---------------------------------------------------------- *
		 * Print the public key information and the key in PEM format *
		 * ---------------------------------------------------------- */
		/* display the key type and size here */
		  if (pkey) {
		    switch (pkey->type) {
		      case EVP_PKEY_RSA:
			fprintf(stdout,"%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
			PEM_write_PUBKEY(stdout, pkey);
			break;
		      case EVP_PKEY_DSA:
			fprintf(stdout,"%d bit DSA Key\n\n", EVP_PKEY_bits(pkey));
			break;
		      default:
			fprintf(stdout,"%d bit non-RSA/DSA Key\n\n", EVP_PKEY_bits(pkey));
			break;
		    }
		  }
		return pkey;
	}
	
/**
 * Add the new client to the client list
 * Second argument gives the certificate of the client
 * Third argument is the socket stream of the ssl client
 */
	int ClientList::add(long clientIP,X509 *cert,SSL* ssl) 
	{
		if(numClients < MAX_CLIENT_LIST) {
			this->clientIP[numClients]=clientIP;
			this->certificate[numClients]=cert;
			this->sslList[numClients] = ssl;
			this->status[numClients]=SLEEP;
			this->LastActivity[numClients]=time(0);
			printf("Added Client %d\n",numClients);
			/* save user ID and certificate to persistent store */
			return numClients++;
		}
		return 0;
	}

/**
 * Update the active users in the client list
 */
	int ClientList::updateStatus(){
		long now=time(0);
		for(int i=1;i<numClients;i++)
		if((now - LastActivity[i]) < 10000) {
			status[i]=ACTIVE;
		}
		return 0;
	}
