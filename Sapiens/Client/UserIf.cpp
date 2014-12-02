#include "UserIf.h"
#include <iostream>
#include <stdlib.h>
#include <string.h>
using namespace std;


	UserIf::UserIf(){

	}
/**
 * mainMenu: displays the main menu
 * 
 */ 
	int UserIf::mainMenu()
	{
		cout<<"PB173: SECURE VIDEO CONFERENCING SYSTEM"<<endl;
		cout<<"---------------------------------------"<<endl;
		cout<<"0. EXIT"<<endl;
		cout<<"1. List Active Users"<<endl<<endl;	
		return SUCCESS;
	}
/**
 * showUser: reads the client list and prints their id on UI screen
 * 
 * @param clientInfo pointer to client list 
 * @param len number of clients in the list
 */
	int  UserIf::showUser(ClientInfo* clientInfo, int len)
	{
		cout<<"List of Active users:"<<endl;
		int  i=0 ;
		cout<<"0. EXIT"<<endl;
		ClientInfo* temp = clientInfo;
		while(temp)
		{
			i++;
			cout<<i<<". "<<temp->id<<endl;
			temp = temp->next;
		}
		cout<<"Select the client to begin connection"<<endl<<endl;
		return SUCCESS;

	}	
/**
 * chat : displays the cliendID and message 
 * <p> Not being used in current version
 */	
int  UserIf::chat( ClientInfo clientInfo, unsigned char* msg , int len)
	{
		char* str = (char*)malloc(len+1);
		strncpy(str, (char*)msg, len);
		str[len] = 0;
		cout<<clientInfo.id<<"\t: "<<str<<endl;
		free(str);
		 return SUCCESS;

	}
/**
 * message: to display a message stored in buffer of given len
 * 
 */
	int  UserIf::message(char* msg, int len)
	{
		char* str = (char*)malloc(len+1);
                strncpy(str, msg, len);
                str[len] = 0;
                cout<<str<<endl;
		free(str);
		 return SUCCESS;

	}
/**
 * display: to display null terminated string on display screen.
 * 
 * 
 */
	int UserIf::display(char* msg)
	{
		cout<<msg<<endl;
	 return SUCCESS;

	}

