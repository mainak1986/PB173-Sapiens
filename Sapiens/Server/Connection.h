#ifndef __CONNECTION_H
#define __CONNECTION_h

#include <time.h>
#include<stdio.h>
#include "common.h"

/**
 * Connection List class maintains the list of clients
 * which are communicating 
 * It maintains the call duration
 * Used to check the client is busy or in any other call
 */
class ConnectionList
{
	int client1[MAX_CLIENT_LIST]; /** Maintains the list of client connected to*/
	int timeStart[MAX_CLIENT_LIST]; /** Start of the communication */
	//timeElapsed[MAX_CLIENT_LIST];
	int connected[MAX_CLIENT_LIST]; /** Connect status of each client */
public:
	/** This function will be called when a connection is about to start*/
	int startConnection(int clientID1,int clientID2);
	/** Check whether any connection is present between client ID1 and ID2 */
	int hasConnection(int clientID1,int clientID2);
	/** Terminate the session between the clients */
	int terminateConnection(int clientID1,int clientID2);
	/** Termincate the given connection */
	int terminateConnection(int connectionID);
	/** Check if the client is busy in another communication */
	int isConnected(int clientID);
};

#endif
