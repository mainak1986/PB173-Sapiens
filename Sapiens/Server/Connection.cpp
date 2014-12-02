#include "Connection.h"

/**
 * starting a connection between the clients passed as argument
 * return the connection ID of the connection between the clients
 */
	int ConnectionList::startConnection(int clientID1,int clientID2)
	{
		if(clientID1 > MAX_CLIENT_LIST || clientID2 > MAX_CLIENT_LIST) return 0;
		int connectionID = (clientID1 < clientID2)? clientID1:clientID2;
		client1[connectionID]=(clientID1 > clientID2)? clientID1:clientID2;
		timeStart[connectionID] = time(0);
		connected[clientID1]=1;
		connected[clientID2]=1;
		return connectionID;
	}

/**
 * This function checks if the client having ID1 is connected to client having ID2
 */
	int ConnectionList::hasConnection(int clientID1,int clientID2)
	{
		if(clientID1 > MAX_CLIENT_LIST || clientID2 > MAX_CLIENT_LIST) return 0;
		int connectionID = (clientID1 < clientID2)? clientID1:clientID2;
		return (client1[connectionID]==((clientID1 > clientID2)? clientID1:clientID2));
	}

/**
 * This function is called when the communication between the clients is finished
 */
	int ConnectionList::terminateConnection(int clientID1,int clientID2) {
		if(clientID1 > MAX_CLIENT_LIST || clientID2 > MAX_CLIENT_LIST) return 0;
		if(hasConnection(clientID1,clientID2)) {
			int connectionID = (clientID1 < clientID2)? clientID1:clientID2;
			terminateConnection(connectionID);
		}
		return 0;
	}

/**
 * This function needs to be called when the connection having the connection ID is termincated
 */
	int ConnectionList::terminateConnection(int connectionID)
	{
		if(connectionID > MAX_CLIENT_LIST) return 0;
		if(timeStart[connectionID] == 0) {
			printf("Invalid connection ID\n");
			return 0;
		}
		int timeElapsed=time(0) - timeStart[connectionID];
		int clientID1 = connectionID;
		int clientID2 = client1[connectionID];
		//Account.charge(clientID1,clientID2,timeElapsed);
		printf("Call Duration between %d and %d: %d units \n",clientID1, clientID2, timeElapsed);
		connected[clientID1] = 0;
		connected[clientID2] = 0;
		timeStart[connectionID] = 0;
		return timeElapsed;
	}

/**
 * This function given whether the given client is BUSY,
 * i.e., connected to some client for connection
 */
	int ConnectionList::isConnected(int clientID)
	{
		if(clientID > MAX_CLIENT_LIST) return 0;
		return connected[clientID];
	}
