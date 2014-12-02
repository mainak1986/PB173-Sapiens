#ifndef __SESSION_H
#define __SESSION_H

#include "encryptor.h"
#define SEND 1
#define RCV 0
class Session
{
public:
struct Key key;
struct ClientID dest;
int sendCount;
int recvCount;
encryptor e;
};

#endif
