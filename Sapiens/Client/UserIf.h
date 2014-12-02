#ifndef DISPLAY_H
#define DISPLAY_H
#include "type.h"
class UserIf
{
public:
	UserIf();
	int mainMenu();
	int showUser(ClientInfo* clientInfo, int len);	
	int chat(ClientInfo clientInfo, unsigned char* msg, int len);
	int message(char* msg, int len);
	int display(char* msg);	// Display a string.
	

};

#endif //DISPLAY_H
