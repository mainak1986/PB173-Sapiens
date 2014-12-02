#ifndef __TYPE_H
#define  __TYPE_H
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

struct ClientID
{
	unsigned int value;
};
struct Key
{
	int value;
};

#include "session.h"
/*
struct Session
{
struct Key key;
struct ClientID dest;
int sendCount;
int recvCount;
};
*/

typedef X509 Cert;

struct ClientInfo
{
int id;
//struct Client client;
struct ClientInfo *next;
};



#define LOGFILE "logfile.txt"
#define PACKET_LEN 1024
enum {REGISTER_NEW_USER,
GET_ACTIVE_USER_LIST,
HELLO,
CALL_USER,
CALL_REQUEST,
DATA,
FILE_DATA,
TERMINATE_SESSION,
TERMINATE};

enum { FAILURE, SUCCESS};
#endif //MYTYPE_H
