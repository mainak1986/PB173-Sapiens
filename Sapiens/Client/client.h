/*
CLIENT_ HEADER


PB173
Team: Sapiens
*/

#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include<string.h>
#include <pthread.h>
#include <gmp.h>

#include "UserIf.h"
#include "type.h"
#ifndef FAIL
#define FAIL    -1
#endif

#ifndef CONFIG
#define CONFIG
#define HOSTNAME 	"127.0.0.1"
#define PORT_NUMBER	5000
#define PORT_NUMBER2	5001
#define CERT_FILE	"client.crt"
#define KEY_FILE	"clientkey.pem"
#endif	// CONFIG

#define DATA_LEN 1000
class Client
{
// Operations
public:
Client(UserIf*);
Client();
~Client();
int initSSL();
int setpassword(const char *p);
int loadCertificates();
int openConnection();
int  startSSL(unsigned char* , int* len);
int  stopSSL(unsigned char* , int* len);
int registerToServer(unsigned char* , int* len);
int unregisterOnServer(unsigned char* , int len);
int initiateChatSession(int destClient);
int terminateChatSession();
int getActiveUserList( ClientInfo* &clientList, int* len );
int receiveData(unsigned char* data , int len);
int sendData(unsigned char* data, int len);
int getAccountStatus(ClientInfo* client);
void* listener(void*);
void* worker(void*);
int isconnected();

private:
int  initCTX(void);
int  showCerts();
int  verifyCert(X509*);    
int  setHostAndPort();
int setCertFile();
int  setKeyFile();
int getCertificate(Cert*);
int setCertificate(Cert*);
int initLog();

// Attributes
    int serverid;
    int clientid;
    FILE* logfp; 
    SSL_CTX *ctx;
    int server;
    int server2;
    SSL *ssl;
    SSL *ssl2;
    Cert* myCert;
    Cert* serverCert;
    Session* session;
    char hostname[16];
    int port;
    int port2;
    char CertFile[100];
    char KeyFile[100];
    char passwd[100];
    char isActive;
    UserIf* ui;
	int isBusy;	// in a chat session
	pthread_t thrListen;

};

#define getid() getpid()
//#define getid() (clientid)?clientid:getpid()
#endif // CLIENT_H

