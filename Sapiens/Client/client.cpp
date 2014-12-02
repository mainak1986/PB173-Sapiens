/*
 *Client class definition
 *
 *PB173
 *Team: Sapiens
 */
#include <signal.h>
#include "client.h"
#include "packet.h"
//#include "UI.h"
#define DEBUG
/** sslListener: This is the function for listener thread. 
 * It calls executes the listener function of client object on the provided *client object.
 *  
 * @param Client object of client class. This object is the one created in main
 * @return NULL 
 * */
void * sslListener(void* obj)
{
	Client * client  = (Client *) obj;
	client->listener(NULL);
	return NULL;
}


/**
 * Client constructor: Takes the User interface object and uses it to initialize class attribute of same type.
 *
 * @param UserIf object of user interface class
 */
Client::Client(UserIf* myUi)
{
	setHostAndPort();
	setCertFile();
	setKeyFile();
	//logfp = fopen(LOGFILE, "a");
	initLog();
	isBusy = FALSE;	
	ui = myUi;	
	
}

Client::Client()
{

}

/**
 * Client desctructor: Kill session and listener thread.
 * 
 */
Client::~Client()
{
	if(session) delete session;
	pthread_kill(thrListen, 9);
}

/**
 * initLog: 
 * Initializes the logfile destination. In debug mode this is set to stdout. But in release mode, it is set to a logfile. release mode has not been tested yet.
 * 
 *  
 */
int Client::initLog()
{
	#ifdef DEBUG
	logfp = stdout;
	 //DEBUG
	#else
	logfp = fopen(LOGFILE, "a");
	if(logfp ==NULL)
	{
		printf("Can not open log file.\t Terminating \n");
		return 1;
	}
	#endif
	return 0;
}

/**
 * initSSL : initializes the SSL library and context. 
 * 
 */
int Client::initSSL()
{
   int ret = 0;	
   SSL_library_init();
   initCTX();
   return ret;
} 

/**
 * setpassword: To set the password for accessing certificate. In debug version *this is used primariry for automating extraction of private key from *certificate using a passphrase. 
 * Not to be used like this in the release version.
 * 
 * @param password is the passphrase for getting private key from certificate
 * @return length of password in case of success or in failure.
 */
int Client::setpassword(const char *passwd)
{
	int size = sizeof(this->passwd);
	int ret = strlen(passwd);
	if(size > ret) {
		strcpy(this->passwd,passwd);
		return ret;
	}
	return 0;
} 
    //Added the LoadCertificates how in the server-side makes.    

/**
 * loadCertificates: Loads the certificate from certificate file and extract information from it. Can be expanded to get public and private keys and store them for assymetric encryption.
 * 
 */
int Client::loadCertificates()
{
 /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(logfp);
        return 1;;
    }
    SSL_CTX_set_default_passwd_cb_userdata(ctx,(void *)passwd); /* TODO: Ask from user */
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(logfp);
        return 1;;
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(logfp, "Private key does not match the public certificate\n");
        return 1;;
    }
    return 0;
}

/**
 * openConnection: Opens a raw socket connection to server
 * 
 *  @return 0 on success and 1 on failure
 */
int Client::openConnection()
{   
    struct hostent *host;
    struct sockaddr_in addr;
    if(logfp)fprintf(logfp,"CLIENT %d: OPEN CONNECTION\n",getid());
    if(logfp)fprintf(logfp,"CLIENT %d: GET HOST BY NAME\n",getid());
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
	fprintf(logfp,"CLIENT %d: openConnection: gethostbyname..%s\n",getid(),hostname );
        return 1;
    }
    if(logfp)fprintf(logfp,"CLIENT %d: INITIALIZE SOCKET\n",getid());
    server = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if(logfp)fprintf(logfp, "CLIENT %d: CONNECT\n",getid());
    if ( connect(server, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(server);
        perror(hostname);
	fprintf(logfp, "CLIENT: openConnection: connect...\t Failed\n");
	printf("CLIENT %d: OPEN CONNECTION ..... FAILED",getid());
        return 1;
    }
    //For SIDECHANNEL
//    server2 = socket(PF_INET, SOCK_STREAM, 0);
//    addr.sin_port = htons(port2);
//    if(logfp)fprintf(logfp, "CLIENT %d: CONNECT\n",getid());
//   if ( connect(server2, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
//    {
//        close(server2);
//        perror(hostname);
//        fprintf(logfp, "CLIENT: openConnection: connect side channel...\t Failed\n");
//        printf("CLIENT %d: OPEN CONNECTION SIDE Channel..... FAILED",getid());
//        return 1;
//    }
 
    if(logfp)fprintf(logfp, "CLIENT %d: OPEN CONNECTION >>>>> SUCCESS\n",getid());
    return 0;
}

int  Client::initCTX(void)
{  

    //SSL_METHOD *method;
   
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
//    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(SSLv3_client_method());   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(logfp);
        return 1;
    }
    return 0;
}

/**
 * showCerts: Extracts the information from certificate. Displays the public key. Future scope: Public key to be used for assymmetric encryption and signing.
 * 
 * @return : 0 on success and 1 on failure
 */
int Client::showCerts()
{   X509 *cert;
    char *line;
    int ret=0;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    /******************************************/
/* ---------------------------------------------------------- *
 *  * Extract the certificate's public key data.                 *
 *   * ---------------------------------------------------------- */

EVP_PKEY *pkey = NULL;
if ((pkey = X509_get_pubkey(cert)) == NULL)
    printf("Error getting public key from certificate");

   /* ---------------------------------------------------------- *
     *  * Print the public key information and the key in PEM format *
     *   * ---------------------------------------------------------- */
   /* display the key type and size here */
   if (pkey) {
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        printf("%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
        PEM_write_PUBKEY(stdout, pkey);
        break;
      case EVP_PKEY_DSA:
        printf("%d bit DSA Key\n\n", EVP_PKEY_bits(pkey));
        break;
      default:
        printf("%d bit non-RSA/DSA Key\n\n", EVP_PKEY_bits(pkey));
        break;
    }
  }

/***********************************************/


    if ( cert != NULL )
    {
        printf("Client %d: Server certificates:\n",getid());
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Client %d: Subject: %s\n",getid(), line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Client %d: Issuer: %s\n",getid(), line);
        free(line);       /* free the malloc'ed string */
	// Verify certificate. returns 0 on success		
	if(verifyCert( cert ))
	{
	fprintf(logfp, "Client %d: Certificate verification failed...\n",getid());	
	ret = 1;
	}

        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        fprintf(logfp, "Client %d: No certificates.\n",getid());


    return ret;
}

/**
 *startSSL: creates SSL connection on the opened socket connection. In this debug version, this function sends a test "Ahoj" message to server and receives it reply back. This function increases the testability to observe the data from server, thus verifying the connection establishment.
 *
 * @param response [out] stores the reponse of server for the Ahoj message. 
 * @param len  [out] this function sets length of the response buffer.
 *
 * @return 0 on success and 1 on failure
 */
int Client::startSSL( unsigned char* response, int * len)
{
    int ret =0;
    int bytes;
    unsigned char buf[PACKET_LEN];	
    if(logfp)fprintf(logfp,"CLIENT %d:STARTSSL:ssl_new\n",getid());
    ssl = SSL_new(ctx);      /* create new SSL connection state */
//    ssl2 = SSL_new(ctx);
    if(logfp)fprintf(logfp,"CLIENT %d:STARTSSL:ssl_set_fd",getid());
    if(SSL_set_fd(ssl, server)) 
	if(logfp)fprintf(logfp,">>>>SUCCESS%d\n",getid());
//    if(SSL_set_fd(ssl2, server2))
//        if(logfp)fprintf(logfp,">>>>SIDE CHANNEL >>>>SUCCESS\n",getid());
   
/* attach the socket descriptor */
    if(logfp)fprintf(logfp,"CLIENT %d:STARTSSL:ssl_connect\n",getid());
//    if ( SSL_connect(ssl2) == FAIL )   /* perform the connection */
//        {//ERR_print_errors_fp(stderr);
//        ret =1;
//        fprintf(logfp,"CLIENT %d:STARTSSL:ssl_connect to side channel......FAILED\n",getid());
//        }

    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        {//ERR_print_errors_fp(stderr);
	ret =1;
	fprintf(logfp,"CLIENT %d:STARTSSL:ssl_connect......FAILED\n",getid());
	}
    else
    {   
	if(logfp)fprintf(logfp,"CLIENT %d:STARTSSL:ssl_connect>>>>>>>SUCCESS\n",getid());
	char msg[PACKET_LEN] = {0};
	struct Packet *p= new Packet();
	memset(p, 0, PACKET_LEN);
	memcpy(p->buffer,"Ahoj",5);
	p->cmd = HELLO;
	memcpy(msg,(void *)p,sizeof(msg));
        if(logfp)fprintf(logfp,"Connected with %s encryption\n", SSL_get_cipher(ssl));
        showCerts();        /* get any certs */
        if(logfp)fprintf(logfp,"Client %d:Sending Ahoj packet to server...\n",getid());
	SSL_write(ssl, msg, sizeof(msg));   /* encrypt & send message */
	bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
	memset(p, 0, PACKET_LEN);
	memcpy((void *)p,buf,sizeof(buf));
        printf("Received: \"%s\"\n", p->buffer);
	delete(p);
    }

	
	*len = bytes;
	response  = (unsigned char*)malloc(bytes);
	memcpy(response, buf, bytes);
	if(logfp)fprintf(logfp,"CLIENT %d:STARTSSL: COMPLETED\n",getid());
	return ret;
}

/**
 * registerToServer: sends the registration request to server and waits for its response. A successful response from server, contains the unique client Id assigned by the server. This clientID is saved in client attributes. And used for all further communications, during this client<-->server session.
 * out parameters are not being used at the moment. :( 
 * @param response [out]stores the reponse of server for the register request. 
 * @param len  	[out]this function sets length of the response buffer.
 *
 * @return 0 on success and 1 on failure
 */
int Client::registerToServer( unsigned char* response, int* len )
{
	int ret=0;
	int bytes;
	char msg[PACKET_LEN];
	struct Packet *p = new Packet();
	memset(p, 0, sizeof(Packet) );
	unsigned char buf[PACKET_LEN];
	p->cmd = REGISTER_NEW_USER;
	printf("Client %d: Registering to server...\n",getid());
	memcpy(msg,(void *)p,sizeof(msg));
	SSL_write(ssl, msg, PACKET_LEN);		
	bytes = SSL_read(ssl, buf, PACKET_LEN);
	buf[bytes] = 0;
	memcpy((void *)p,buf,sizeof(buf));
	//printf("Client %d: ServerResponse:\"%c%c%d%d%s\"\n",getid(), buf);
	//if(strcmp((const char*)msg, (const char*)buf)) ret = 1;
	
	//*len = bytes;
	//response = (unsigned char*)malloc(bytes);
	//memcpy(response, buf, bytes);
	//memcpy((void *)&clientid,response+2,4);
	//memcpy((void *)&serverid,response+6,4);
	if(p->ack) {
		clientid = ntohl(p->dst);
		serverid = ntohl(p->src);
		fprintf(logfp, "CLIENT: Register on server..SUCCESS wih client ID = %d\n",p->dst);
		fprintf(logfp, "CLIENT: Register on server..SUCCESS \n");
		ret = SUCCESS;

	//	pthread_create(&thrListen, NULL , sslListener, (void*)this);
	}
	else
	{
		fprintf(logfp, "CLIENT:: Register on server.. FAILURE");
		ret = FAILURE;	
	}
	printf("Client %d: ServerResponse:\n",getid());
                                for(int i=0;i<100;i++) {
                                        printf("%c ",p->buffer[i]);
                                }
	printf("\n");
	delete(p);
	return ret;

}

/**
 *getActiveUserList: creates a request to get active user list from server and waits for its reply. Recieved information is used to populate the client list, which is then returned back to the calling function.
 * <p>
 * If not present, creates the listener thread. From now on , all SSL read operations are handled by the listener thread. 
 * <p>
 * Currently, behaviour is unknown if the clients closes a chat session and tries to restart it. And out parameters are not being used now as well.
 *  
 * @param cList  [out]
 * @param len 	[out]
 * 
 */
int Client::getActiveUserList( ClientInfo *&cList, int* len )
{
	int ret=0;
	cList =NULL;
	int bytes;
	char msg[PACKET_LEN];
	char response[PACKET_LEN];
	struct Packet *p= new Packet();
	p->cmd = GET_ACTIVE_USER_LIST;
	p->src = clientid;
	p->dst = serverid;
	unsigned char buf[PACKET_LEN];
	printf("Client %d: get Active user list\n",getid());
	printf("Client %d: get Active user list\n",clientid);
	p->src = htonl(p->src);
	p->dst = htonl(p->dst);
	memcpy(msg,(void *)p,sizeof(msg));
	SSL_write(ssl, msg, PACKET_LEN);		
	do {
		bytes = SSL_read(ssl, buf, PACKET_LEN);
		buf[bytes] = 0;
		printf("Client %d: ServerResponse:\n",getid());
                                for(int i=0;i<100;i++) {
                                        printf("%x ",buf[i]);
                                }
		memcpy((void *)p,buf,sizeof(buf));
		printf("Client %d: ServerResponse:\n",getid());
                                for(int i=0;i<100;i++) {
                                        printf("%x ",p->buffer[i]);
                                }
		printf("\n");
		int i=0;
		int id;
		id = p->buffer[i]<<24|p->buffer[i+1]<<16|p->buffer[i+2]<<8|p->buffer[i+3];
		printf("id:%d\n",id);
		while(id)
		{
	//	fprintf(stdout,"i=%d,p.buffer[i]=%x\n",i,p.buffer[i]);
			 {
					ClientInfo *x=new ClientInfo;
					if(!x) {
						printf("Outof memory\n");
						return 1;
				
						}
					x->id = (int)id;
					printf("User: %d\t", x->id);
					x->next = cList;
					cList=x;
				}
			i+=4;
			//id = (short)p.buffer[i+1];
			id = p->buffer[i]<<24|p->buffer[i+1]<<16|p->buffer[i+2]<<8|p->buffer[i+3];
		}
	}while(p->continued);
	printf("List of Active users:are:\t");
	fflush(stdout);
	ClientInfo *temp = cList;
	while(temp) {
		printf("%d\t",temp->id);
		temp=temp->next;
	}
	printf("\n");
	// Listener thread... begin the thread if not already there.
	if(!thrListen)	
	 pthread_create(&thrListen, NULL , sslListener, (void*)this); 
	//response = &p;
	//printf("Client %d: ServerResponse:\"%s\"\n",getid(), p.buffer);
	//if(strcmp((const char*)msg, (const char*)buf)) ret = 1;
	
	//*len = bytes;
	//response = (unsigned char*)malloc(bytes);
	//memcpy(response, buf, bytes);
	delete(p);
	return ret;

}

int Client::verifyCert( X509* cert)
{
	// TBD
	// verifciation of certificate with CA
	return 0; // On success
}

/**
 * stopSSL: Will send a Termination request to server and wait for its response.  This response is observable.
 *  @param response  [out]
 *  @param len 	[out]
 * 
 */
int  Client::stopSSL(unsigned char* response, int * len)
{

	*len =0;
	if(ssl==NULL) return 0;
        int bytes;
        char msg[1];
        msg[0] = TERMINATE_SESSION;
        unsigned char buf[1024];
        printf("CLIENT %d:STOPSSL:Sending terminate signal to server...\n",getid());
        SSL_write(ssl, msg, strlen(msg));
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = 0;
        printf("Client %d: ServerResponse:\"%s\"\n", getid(), buf);

  	SSL_free(ssl);	 
	//SSL_free(ssl2);
  	close(server);         /* close socket */
	//close(server2);
   	SSL_CTX_free(ctx);        /* release context */

	*len = bytes;
        response = (unsigned  char* )malloc(bytes);
        memcpy(response, buf, bytes);

	return 0;
}

/**
 * initiateChatSession: Creates a call begin packet for destination client and writes it on ssl channel. destClient value should be valid. For all invalid values, connection attempt will fail.
 *  @param destClient
 *  
 */
int Client::initiateChatSession(int destClient)
{
	int ret=0;
        int bytes;
        char msg[PACKET_LEN];
        char response[PACKET_LEN];
        struct Packet *p=new Packet();
        p->cmd = CALL_USER;
        p->src = htonl(clientid);
        p->dst = htonl(destClient);
        unsigned char buf[PACKET_LEN];
        printf("Client %d: Initiate chat session for dest: %d\n",clientid, destClient);
        memcpy(msg,(void *)p,sizeof(msg));
	delete(p);
        SSL_write(ssl, msg, PACKET_LEN);
	return SUCCESS;
/*	bytes = SSL_read(ssl, buf, PACKET_LEN);
        buf[bytes] = 0;
        printf("Client %d: ServerResponse:\n",clientid);
        for(int i=0;i<100;i++) {
                                     printf("%x ",buf[i]);
                               }
        memcpy((void *)&p,buf,sizeof(buf));
	if(p.cmd==CALL_USER)
	{
		printf("%d:Init chat session: Wrong cmd in recv packet\n", clientid);
		return -1;
	}
	switch(p.ack)
	{
	case SUCCESS:
		printf("%d:Successfully connected to: %d\n", clientid, destClient);
		// Create session object
		session = new Session();	
	
		return SUCCESS;
		
	case FAILURE:
		printf("%d: Could not connect to :%d\n", clientid, destClient);
		return FAILURE;	
		break;
	default:
		printf("%d: Could not connect to :%d\n", clientid, destClient);
		printf("Illegal ACK from server\n");
                return FAILURE;
		break;

	}
*/
}
    
int  Client::setHostAndPort()
{
	strcpy(hostname, HOSTNAME);
	port = PORT_NUMBER;
	return 0;
}

int   Client::setCertFile()
{
	strcpy(CertFile, CERT_FILE);
	return 0;
}

int  Client::setKeyFile()
{
	strcpy(KeyFile, KEY_FILE);
	return 0;
}
 
/**
 * listener: waits on a blocking read call and handles all the packets coming from server. It can handle call request packets on both sides ie call initiator and call receiver, data packets and termination packets. Different packets are processed differently here. As a result of processing, ssl write and/or ui write or any other processing function may be called.
 * <p>
 * FUTURE: Extend it to handle all possible packets for example: register request replies, user list replies, etc. And handle all ssl read operations in this function.
 */
void* Client::listener(void*)
{

	// Read messages coming from server and send resonse to server or to UI
	int readBytes;
	struct Packet * packet = new Packet();
	unsigned char buf[PACKET_LEN];
	unsigned char reply[PACKET_LEN];
	char forward[PACKET_LEN];
	int temp;
	memset(buf, 0, sizeof( buf));
	while(1)
	{
		memset(reply, 0 , PACKET_LEN);	
		memset(forward, 0 , PACKET_LEN);
		readBytes = SSL_read(ssl, buf, sizeof(buf));
		//printf("READBYTES %d\n", readBytes);
		//if(!readBytes)continue;	// No bytes read
		if(readBytes<1)
		{
		//	printf("CLIENT:LISTENER:: ERROR %d\n",SSL_get_error(ssl, readBytes));
			continue;
		}
		if(readBytes!=1024)
		{
		fprintf(logfp, "CLIENT::Listener:: not enought data in received packet\n");
		continue;
		}
		printf("CLIENT :: Listener:: Received= \n");
		for(temp =0; temp<100; temp++)
		printf("%2x",buf[temp]);
		printf("\n");
		memcpy(packet, buf, sizeof(buf));
		switch(packet->cmd)
		{
			case HELLO:
				packet->ack = SUCCESS;
				memcpy(reply, packet, sizeof(struct Packet));
				strcpy(forward, "Recieved hello from server\n");				break;
			case CALL_REQUEST:
				if(isBusy == TRUE) packet->ack = FAILURE;
				else 
				{	
					packet->ack = SUCCESS;
					isBusy = TRUE;
					session = new Session();
                                	session->dest.value = ntohl(packet->src);  
				}	
				// Swap source and destination
				temp = packet->src;
				packet->src = packet->dst;
				packet->dst = temp;
				fprintf(logfp,"CLIENT::Listener:: CALLREQUEST received %d -> %d\n",htonl(packet->src), htonl(packet->dst));
			
				fprintf(logfp,"CLIENT::Listener:: CALLREQUEST received\n");
				memcpy(reply, packet, sizeof(struct Packet));
		printf("CLIENT :: Listener:: Sending= \n");
		for(int i =0; i<100; i++)
		printf("%2x ",reply[i]);
		printf("\n");
				sprintf(forward, "Received request for connection from %d", packet->src);
				break;	
			case CALL_USER:
				if(packet->ack == SUCCESS)
				{
					sprintf(forward, "Connected to client#%d\n", ntohl(packet->dst));			
					printf(forward);
					session = new Session();
					session->dest.value = ntohl(packet->src);	
				}
				else if(packet->ack == FAILURE)		
				{
					sprintf(forward, "Could not connect to client#%d\n",ntohl(packet->dst));
				printf(forward);	
				}
				break;
			case DATA:
				if(session==NULL)
					{
						printf("Listener:: Received data::Not in session\n");
						break;
					}
				if(ntohl(packet->src) != session->dest.value)
				{
					printf("Listener:: Destination of received data and my session destination mismatch %d, session = %d\n",ntohl(packet->dst),session->dest.value);
					break;
				}	
				receiveData(packet->buffer, packet->len);
				break;
			case TERMINATE:
				isBusy = FALSE;
				packet->ack = SUCCESS;
				memcpy(reply, packet, sizeof(struct Packet));
				strcpy(forward, "Terminating connection\n");					break;
			default:
				sprintf(forward, "Invalid request from server\n");  		
		}
		if(reply[0])
		{
			SSL_write(ssl, reply, sizeof(reply));
		}
		if(forward[0])
		{
			//ui->display(forward);
		}
		if(reply[0]==TERMINATE)
			break; // come out of while(1) loop
		
	}
return NULL;
}

/**
 *For further extension and organised code. Sorry no time to reorgnise! 
 */
void* Client::worker(void*)
{
	// Read requests from user and Write them on SSL
	return NULL;
}
/**
 * isconnected: checks if a chat session with other client is active. 
 * 
 */
int Client::isconnected()
{

	sleep(1);
#ifdef DEBUG
	printf("session = %p\n",session);
#endif
	if(session) return SUCCESS;
	return FALSE;

}
/**
 *  sendData: 
 * This function is used by UI during chat session to send data to the other end. It creates the packet for data and sends it.
 *  <p>
 * Every data packet is encrypted before it is written into the packet.
 * 
 * @param data buffer of plain text data as given from UI
 * @param len  length of buffer in bytes
 */
int Client::sendData(unsigned char * data , int len)
{
	if(session==NULL)
		return FAILURE;
	if(data==NULL)
		return FAILURE;
	if(len==0)
		return FAILURE;
	unsigned char buf[PACKET_LEN];			
	Packet * packet = new Packet();
	packet->cmd  = DATA;
	packet->src  = clientid;
	packet->dst  = session->dest.value;
	printf("Send Data: %d -> %d\n",packet->src, packet->dst);
	fflush(stdout);
	
	// larger packets not implemented now. Can be implemented using continues field in packet.
	if(len > (int)sizeof(packet->buffer))
	len = sizeof(packet->buffer);
	//Encrypt the data here...
	//
	//
	
	packet->src = htonl(packet->src);
	packet->dst = htonl(packet->dst);
	session->e.crypt(data, (len+15)&~0xF, SEND);
	memcpy(packet->buffer,data, len );
	packet->len = len;
	memcpy(buf, packet, PACKET_LEN);
	printf("SENDDATA:: Packet \t");
	for(int i=0;i<100;i++)
	printf("%2x",buf[i]);
	printf("\n");
	SSL_write(ssl,buf, PACKET_LEN );

	return SUCCESS;
}

/**
 * receiveData:
 * It handles the data coming form the server side. This checks if the packets received are for key establishment for data exchange. 
 * <p>
 * All normal data packets are encrypted when received therefore, they are decrypted here and then forwarded to the UI for display.
 * 
 *  @param data buffer of either plain text or encrypted data .
 *  @param len  length of buffer in bytes
 * 
 */
int Client::receiveData(unsigned char* data, int len)
{
//	ui->display(session->dest.value);
	char* str = (char*)malloc(len+1);
	session->e.crypt(data, (len+15)&~0xF, RCV);
	strncpy(str, (char*)data, len);
	str[len] = 0;
	ui->display(str);	
	printf("\nReceived data:\t");
	printf(str);
	printf("\n");
	free(str);
	return SUCCESS;
}
