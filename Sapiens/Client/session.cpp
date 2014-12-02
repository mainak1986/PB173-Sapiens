
#include "type.h"
class Session
{
public:
struct Key key;
struct ClientID dest;
int sendCount;
int recvCount;
encryptor e;
};
