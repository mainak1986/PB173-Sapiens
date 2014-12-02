//SSL-Client.c


#include "client.h"
#include "type.h"
#include "UserIf.h"

int main(int argc, char *argv[])
{ 
  
	int clientid;
//    	UserIf *ui = new UserIf();
    	Client *client = new Client;//(ui);
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
#if 0
// Setup for synchronouse IO multiplexing

	fd_set rfds;
    	struct timeval tv;
    	int retval;

   /* Watch stdin (fd 0) to see when it has input. */
    	FD_ZERO(&rfds);
    	FD_SET(0, &rfds);

   /* Wait up to five seconds. */
    	tv.tv_sec = 1;
    	tv.tv_usec = 0;


// Setup for synch IO multiplexing done


// UI loop
int value = -1;
while(1)
{
	// Display main menu. 
	while(value != 0 || value != 1)
	{
	ui->display("Choose correct option...\n");
	ui->mainMenu();
	scanf("%d",&value);
	}
	if(value==0)
	{
	// Terminate this session.
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
        FD_ZERO(&rfds);
        FD_SET(0, &rfds);
   	do{	
    	retval = select(1, &rfds, NULL, NULL, &tv);
	if (retval==-1) perror("UI sequence:: select()");
	if(retval>0)
	scanf("%d",&value);
	}
	while(retval==0 ||(client->isconnected()!=SUCCESS) );
	printf("Selected value: %d\n", value);
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
	unsigned char data[PACKET_LEN] = "Hi this is me. Lets begin!";
	client->sendData(data, 26);
	printf("Data sent...\n");

	while(1)
	{
	scanf("%s",data);
	client->sendData(data, strlen((char*)data));
	}
	

}


#endif
// UI loop ends
sleep(10);  

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
