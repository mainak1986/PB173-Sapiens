//SSL-Server.h
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <gmp.h>
#include <pthread.h>
#include<iostream>

#include "ClientList.h"
#include "Connection.h"

#ifndef FAIL
#define FAIL    0
#endif
#ifndef SUCCESS
#define SUCCESS    1
#endif

using namespace std;

#define PORTNUMBER 5000
#define LOGFILE "Log.txt"

/**
 * SSL Server is the server class which can be instantiated 
 * for the server functionality.
 */
class SSLServer {
	int port; /** This is the port number on which the server is listening */
	int sd; /** This is the socket descriptor of the server on which it is listening */
	enum {
		CLOSE,  /** Close state */
		INITIALIZED,  /** All member variables are Initialized */
		OPEN,  /** Open state indicates that the socket is open for listen and ready to accept connecions; Before listening the server object should be opened */
		CONNECT /** Connect state,  accepting connections */
	} status; /** Indicates the state of the server */
	char* CertFile; /** Gives the path of the server certificate file */
	char* KeyFile; /** Gives the path of the private key of the server */
	char passwd[100]; /** Password(pass phrase) to be used for not prompting for password when using certificates */
	SSL_CTX *ctx; /** SSL context varible */
	SSL *ssl; /** Variable for passing to separate server thread when a connection is accepted */
	pthread_t thread; /** Thread variable for starting a thread for handling client communications */
	FILE *logfd; /** log file descriptor */

        ClientList *clist; /** This list is used to get the list of clients who are connected to the server */
        ConnectionList *connectList; /** This is used to know whether any client is busy before sending a connection request */
public:
	SSLServer(void); /** Server constructor to initialize the server member variables*/
	SSLServer(int port); /** constructor  which initialized with the port number to which server is going to listen*/
	~SSLServer(void); /**Destructor to free the memory allocated during the initialization in the constructor */
	void setport(int port); /** function to set the server port, should be used before opening the socket */
	int Open(int port); /** open the server socket listening at given port for communication */
	int Open(); /** open the server socket for communication */
	int setpassword(const char *passwd); /** set the password that need to be used for accessing the keys or certificates*/
	int LoadCertificates(char* CertFile, char* KeyFile); /** Load the server certficates which is used for SSL communication */
	X509 *ShowCerts(SSL* ssl); /** Get the client certificate and display or verify */
        int asymmetricEncrypt(unsigned char *message,size_t inlen,unsigned char *cipherMessage,size_t *outlen);
	void* Servlet(); /** Serve the connection -- threadable; called from the thread context */
	int Accept(); /** Accept the connections from client and invoke a thread to handle the connection */
//        int getSD();
 //       SSL_CTX* getCTX();

	//void initDH(unsigned char *number,int );
};

