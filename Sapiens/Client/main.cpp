//SSL-Client.c


#include "client.h"
#include "type.h"
#include "UserIf.h"
/**
 * This function creates the objects of Client class and User Interface, and initializes them. It operates in the following sequence:
 * 1. Initialize SSL connection between client <-->server
 * 2. Get certificates and extract keys from it for future uses
 * 3. Register to server
 * 4. UI loop
 *    4.1 Display Main menu: User may exit by pressing 0 or go ahead by pressing 1
 *    4.2 Get active user list: gets the list from server and displays it.
 *    4.3 User may now either go to 4.1 again or choose a client to connect to
 *    4.4 Choose a client id
 *        4.4.1 UI polls on STDIN , until either user select a client id or some other client sends a connection request.
 *        4.4.2 If user selects a client for communication, it initiates chat session
 *    4.5 Once chat session begins, client can talk to other client in chat session.
 *    4.6 User comes out of chat by pressing CHAT END SEQUENCE: '.' followed by
 *        ENTER.
 *    4.7 User goes back to MainMenu. And get new client list again.
 * 
 */
int main()
{ 
  
    	UserIf *ui = new UserIf();
    	Client *client = new Client(ui);
	ClientInfo *cinfo=0;
 	unsigned char* response=NULL;
 	int len; 
	char passwd[]="client";
	if(!client) {
		printf("Client %d: Count not creat client\n",getid());
	}
/*    if(client->initLog())
	{
	delete client;
	return 1;	
	}
*/
   	if(client->initSSL())
	{
		printf("Client %d: InitSSL...\t\t\tFailed\n",getid());
	}
   	client->setpassword(passwd);
   	if(client->loadCertificates())
	{
		printf("Client %d: LoadCertificates from CA...\tFailed\n",getid());
	}
   	if(client->openConnection())
	{
		printf("Client %d: OpenConnection...\t\t\tFailed\n",getid());
	}
   	if(client->startSSL( response ,&len))	// Initial handshake. Certificate exchange
   	{
		printf("Client %d: StartSSLcommunication \t\tFailed\n",getid());
	}
	if(response)free(response);
	response =NULL;
   	if(client->registerToServer(response ,&len))
	{
		printf("Client %d: Register On Server...\t\tFailed\n",getid());
	}
	if(response)free(response);
	response = NULL;

// Setup for synchronouse IO multiplexing

	fd_set rfds;
    	struct timeval tv;
    	int retval;

   /* Watch stdin (fd 0) to see when it has input. */
    	FD_ZERO(&rfds);
    	FD_SET(0, &rfds);

   /* Wait up to five seconds. */
    	tv.tv_sec = 5;
    	tv.tv_usec = 0;


// Setup for synch IO multiplexing done


// UI loop
int value = -1;
unsigned char data[PACKET_LEN] = "Hi this is me. Lets begin!";
while(1)
{
	// Display main menu. 
	while((value != 0) && (value != 1))
	{
	ui->display((char *)"Choose correct option...\n");
	ui->mainMenu();
	fflush(stdin);
	scanf("%d",&value);
	printf("Value = %d\n", value);
	}
	if(value==0)
	{
	// Terminate this session.
	printf("Recieved value %d. terminating now...\n", value);
	break;
	}

  	if(client->getActiveUserList(cinfo ,&len))
	{
		printf("Client %d: User List from server...\t\tFailed\n",getid());
	}
//	printf("List of Active users are:");
//	fflush(stdout);
//	ClientInfo *temp = cinfo;
//	int count=0;
//	while(temp) 
//	{
//		count++;	// Number of clients in the list
//		printf("%d\t:%d,",count,temp->id);
//		temp=temp->next;
//	}
//	printf("\n");
//	response = NULL;
//	int select;
	ui->showUser(cinfo, len);
  //  do{
   	//printf("Select the destination client");
   	 /* Watch stdin (fd 0) to see when it has input. */
   	do{	
	FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
	tv.tv_sec = 5;
	tv.tv_usec = 0;
    	printf("Beginning of select call\n");
	retval = select(1, &rfds, NULL, NULL, &tv);
	printf("select returned %d\n", retval);
	if (retval==-1) perror("UI sequence:: select()");
	if(retval>0)
	scanf("%d",&value);
	if(FD_ISSET(STDIN_FILENO, &rfds))
	{
	 printf("ENTER NOW::\n ");
	}
	}
	while(retval==0 &&(client->isconnected()!=SUCCESS) );
	if(client->isconnected()!=SUCCESS)
	{
		printf("Selected value: %d\n", value);
		if(value==0)
		{
			// Exit this option and start from MAIN MENU
			continue;

		}
	// use obtained vlaue ie destination client it to connect 
	
 //   } while(select>count || select<0);	// Check for valid input
//
 //   	int destClient;
//	
 //   	temp = cinfo;
 //   	while(temp&&count ) 
//	{	//Find the selected client id from list
//		count--;
//	        destClient = temp->id;
//	        temp = temp->next;
 //   	}

    //Release client  list memory
//	temp = cinfo;
//	while(cinfo)
//	{
//		cinfo = cinfo->next;
//		if(temp)free(temp);
//	}
//	printf("Initiating chat session with %d\n", select);
    		if(client->initiateChatSession(value)!=SUCCESS)
    		{
	//printf("Could not connect to destination. Try later\n");
	//exit(1);
    		}
//sleep(100);
		while(!(client->isconnected() == SUCCESS)); /* Checking for pending status */
		printf("sending data...\n");
		//unsigned char data[PACKET_LEN] = "Hi this is me. Lets begin!";
		client->sendData(data, 26);
		printf("Data sent...\n");
	}
	while(1/*&& session is active*/)
	{

		do{
	        FD_ZERO(&rfds);
	        FD_SET(STDIN_FILENO, &rfds);
	        tv.tv_sec = 1;
	        tv.tv_usec = 0;
	       // printf("Beginning of select call\n");
	        retval = select(1, &rfds, NULL, NULL, &tv);
	       // printf("select returned %d\n", retval);
	        if (retval==-1) perror("UI sequence:: select()");
	        if(retval>0)
	        {
			printf("Sending:: ");
			fflush(stdout);
                	fgets((char*)data, DATA_LEN,stdin);
                	client->sendData(data, strlen((char*)data));
		}
	        }while(retval==0 /*&& session is active*/ );

	}
	

}


// UI loop ends
//sleep(10);  

// Termination sequence.
  if(client->stopSSL(response ,&len))
	{
	printf("Client %d: Stop SSL connection... \t\tFailed\n",getid());
	}

	if(response)free(response);
	response = NULL;
    delete client;
    return 0;
}
