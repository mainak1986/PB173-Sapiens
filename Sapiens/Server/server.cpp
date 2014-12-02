//SSL-Server.c
#include "server.h"
#include "packet.h"

#define DEBUG 1
using namespace std;

//#define FAIL    -1
//#define SUCCESS    0

/**
 * This enum structure which defines the commands that can a client
 * can send to the server
 */
enum {
REGISTER_NEW_USER, /** This is the command for registering the new user */
GET_ACTIVE_USER_LIST, /** This command is send to retrieve the list of active users */
HELLO, /** This is the HELLO message which can be used to ping the server to know the avaiability of the server */
CALL_USER, /** This command packet is send when a client A wants to communicate to client B */
CALL_REQUEST, /** This command packet is send to client B when A wants to talk to B */
DATA, /** This is the data packet which can be transmitted between the clients */
FILE_DATA, /** This is same as data, but only indicates that the file is being transmitted */
CALL_END, /** This is used to terminate the session created between the clients */
TERMINATE /** This is the call for disconnecting the client from the server */
}; 

/**
 * Servletfn is the thread function
 * When a client connects to the server, server accepts the request and 
 * this function is the thread function or start function
 * which will be invoked by the server to handle the communication 
 * between the client and the server
 */
void *Servletfn(void *obj)
{
	SSLServer *server=(SSLServer *) obj;
	server->Servlet();
	return 0;
}

/**
 * This is the constructor of the server class
 * SSL is initiated 
 * and the member variable of the server are initialzed
 * a client list and a connection list will be created
 */
	//Constructor
	SSLServer::SSLServer(void)
	{   
	    SSL_library_init();
	    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	    SSL_load_error_strings();   /* load all error messages */
	    this->ctx = SSL_CTX_new(SSLv3_server_method());   /* create new context from new server-method */
	    if ( this->ctx == NULL )
	    {
		ERR_print_errors_fp(logfd);
		abort();
	    }
	    this->sd=0;
	    this->port = PORTNUMBER;
	    //this->status = CLOSE;
	    this->status = INITIALIZED;
	    this->CertFile = 0;
	    this->KeyFile = 0;
	    memset(this->passwd,0,sizeof(this->passwd));
	    this->ssl = 0;
	    this->clist = new ClientList();
	    this->connectList = new ConnectionList();
		logfd=fopen("Log.txt","a");
		if(logfd==NULL)
			perror("Log");
		if(logfd)fprintf(logfd,"Server Started..\n");
	}


/**
 * This is the constructor of the server class
 * It takes an argument as port to which this server will be listening to
 * SSL is initiated 
 * and the member variable of the server are initialzed
 * a client list and a connection list will be created
 */
	SSLServer::SSLServer(int port)
	{   
	    SSL_library_init();
	    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	    SSL_load_error_strings();   /* load all error messages */
	    this->ctx = SSL_CTX_new(SSLv3_server_method());   /* create new context from new server-method */
	    if ( this->ctx == NULL )
	    {
		ERR_print_errors_fp(logfd);
		abort();
	    }
	    this->port = port;
	    this->sd=0;
	    this->status = INITIALIZED;
	    this->CertFile = 0;
	    this->KeyFile = 0;
	    memset(this->passwd,0,sizeof(this->passwd));
	    this->ssl = 0;
	    this->clist = new ClientList();
	    this->connectList = new ConnectionList();
		logfd=fopen(LOGFILE,"a");
		if(logfd==NULL) 
			perror("Log");
		if(logfd)fprintf(logfd,"Server Started..\n");
	}


/**
 * This is the destructor of the server class
 * The member variable of the server are deallocated like
 * a client list, connection list, certificate file handle, key file handle, etc
 */
	SSLServer::~SSLServer(void)
	{
	    close(sd);          /* close server socket */
		delete clist;
		delete connectList;
	    if(CertFile) free(CertFile);
	    if(KeyFile) free(KeyFile);
	    SSL_CTX_free(ctx);         /* release context */
	    if(logfd)fprintf(logfd,"Server Shutdown..\n");
	    if(logfd) fclose(logfd);
	}


/**
 * This function is used to set the port to which the server will be binding to.
 * This has to be called before listening and accepting the connections
 * Any call to this function after listening will not have any effect
 */
	//Set the port
	void SSLServer::setport(int port) {
	    this->port = port;
	    this->status = INITIALIZED;
	}

/**
 * This function can be called to create a socket and bind for listening
 * This function takes port number as an argument, this port number will be used 
 * by the server fot listening
 */
	int SSLServer::Open(int port)
	{
	    if( this->status != CLOSE) {
		printf("Close the connection first\n");
		return -1;
	    }
	    setport(port);
	    return Open();
	}


/**
 * This function can be called to create a socket and bind for listening
 * 
 */
	int SSLServer::Open()
	{   
	    struct sockaddr_in addr;
	    if( this->status != INITIALIZED) {
		printf("Set the port first\n");
		return -1;
	    }
	    if(this->sd) {
		cout <<"Socket Already Open"<<endl;
		return SUCCESS;
	    }

	    this->sd = socket(PF_INET, SOCK_STREAM, 0);
	    bzero(&addr, sizeof(addr));
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(this->port);
	    addr.sin_addr.s_addr = INADDR_ANY;
	    if ( bind(this->sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	    {
		if(logfd)fprintf(logfd,"Can't bind port %d\n",errno);
		perror("can't bind port");
		abort();
	    }
	    if ( listen(this->sd, 10) != 0 )
	    {
		if(logfd)fprintf(logfd,"Can't configure listening port %d\n",errno);
		perror("Can't configure listening port");
		abort();
	    }
	    status = OPEN;
	    return SUCCESS;
	}

/**
 * This is the function which can be used to set the password
 * to prevent the prompting for password when the certificate will be used
 * by the server for communication
 */
	int SSLServer::setpassword(const char *passwd)
	{
		int size = sizeof(this->passwd);
		int ret = strlen(passwd);
		if(size > ret) {
			strcpy(this->passwd,passwd);
			return ret;
		}
		return 0;
	}

/**
 * This function will load the certificates
 * It takes two arguments
 * CertFile will be the path to the certificate file of the server
 * KeyFile will be the path for the key file
 * This function will verify the path to the certifcate and key file and
 * use the certificae file and private key file
 */
	int SSLServer::LoadCertificates(char* CertFile, char* KeyFile)
	{
	    if( this->CertFile != 0 || this->KeyFile != 0) {
		printf("Certificates already Loaded \n");
		return SUCCESS;
	    };
	    if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
		ERR_print_errors_fp(logfd);

	    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		ERR_print_errors_fp(logfd);

	    /* set the local certificate from CertFile */
	    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
	    {
		ERR_print_errors_fp(logfd);
		abort();
	    }
		//SSL_CTX_set_default_passwd_cb_userdata(ctx,(void *)"pb173"); /* TODO: Ask from user */
	    SSL_CTX_set_default_passwd_cb_userdata(ctx,(void *)this->passwd);
	    /* set the private key from KeyFile */
	    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
	    {
		ERR_print_errors_fp(logfd);
		abort();
	    }
	    /* verify private key */
	    if (!SSL_CTX_check_private_key(ctx))
	    {
		if(logfd)fprintf(logfd, "Private key does not match the public certificate\n");
		abort();
	    }

	    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	    SSL_CTX_set_verify_depth(ctx, 4);

		/* By this time CertFile and Key File are already verified */
	    this->CertFile = (char *)malloc (strlen(CertFile)+1);
	    this->KeyFile = (char *)malloc (strlen(KeyFile)+1);
	    strcpy (this->CertFile, CertFile);
	    strcpy(this->KeyFile, KeyFile);

	    return SUCCESS;
	}

/**
 * This function is used to get the certificate of the clients
 * get the subject and issuer name present in the certificate
 */
	X509 *SSLServer::ShowCerts(SSL* ssl)
	{   X509 *cert;

	    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	    if ( cert != NULL )
	    {
	        char *line;
		if(logfd)fprintf(logfd, "Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		if(logfd)fprintf(logfd, "Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		if(logfd)fprintf(logfd, "Issuer: %s\n", line);
		free(line);
		//X509_free(cert);
		return cert;
	    }
	    else {
		printf("No certificates.\n");
			return 0;
		}
	}

/*
	int SSLServer::asymmetricEncrypt(unsigned char *message,size_t inlen,unsigned char *cipherMessage,size_t *outlen)
	{
		EVP_PKEY_CTX *ctx;
		
		EVP_PKEY *key = NULL;
		if ((pkey = X509_get_pubkey(cert)) == NULL)
    			printf("Error getting public key from certificate");
		ctx = EVP_PKEY_CTX_new(key);
		if (!ctx)
                {
			fprintf(logfd,"\n\tPublic key context cannot be set");
			return FALSE;
		}

	        if (EVP_PKEY_encrypt_init(ctx) <= 0)
                {
			fprintf(logfd,"\n\tPublic key ssl init cannot be set");
			return FALSE;
		}

        	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_OAEP_PADDING) <= 0)
                {
			fprintf(logfd,"\n\t RSA padding cannot be done");
			return FALSE;
		}

		 // Determine buffer length 
	        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
                {
			fprintf(logfd,"\n\tData encryption cannot be done");
			return FALSE;
		}

      		cipherMessage = OPENSSL_malloc(outlen);

      		if (!cipherMessage)
		{
			fprintf(logfd,"\n\tCipher Message memory cannot be set");
			return FALSE;
		}
                

  	        if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
                {
			fprintf(logfd,"\n\tEncryption cannot be done");
			return FALSE;
		}

   	       return TRUE;
	}*/

/**
 * This is the function which handle all the commands from the packets received from client
 */
        void* SSLServer::Servlet()
	{
	    SSL *ssl = this->ssl;

	    if ( SSL_accept(ssl) == FAIL )     /* accept the connections; SSL protocol accept */
		ERR_print_errors_fp(logfd);
	    else
	    {
	        char buf[PACKETSIZE],msg[PACKETSIZE];
	        char reply[PACKETSIZE];
	        int bytes;
	        const char* echo="%s\n\n";
		X509 *cert= ShowCerts(ssl);        /* get certificates */
		int err=0;
		struct Packet *packet=new Packet();
		while(err<5)
		 {				
			memset(buf,0,sizeof(buf));
			bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
			if ( bytes > 0 )
			{
				memset(reply,0,sizeof(reply));
				memcpy(packet,buf,sizeof(buf));
				err=0;
				printf("buf[0]=%d\n",buf[0]);
				fflush(stdout);
				if((packet->cmd > REGISTER_NEW_USER) && (packet->cmd < TERMINATE)){
					int ClientID = this->clist->getClientID(ntohl(packet->src));
					if(ClientID) 
					clist->setActive(ClientID);
				}
				switch(packet->cmd)
			        {
				case HELLO:  //Heartbeat Message
					packet->ack = SUCCESS;
					memcpy(reply,packet,sizeof(struct Packet));
				break;
			
	
				case REGISTER_NEW_USER: 	//Register New User
				{
					if(logfd)fprintf(logfd,"Client Register New msg: \"%s\"\n", packet->buffer);
					int cid = clist->add(clist->getNewID(),cert,ssl); //TODO: use IP of client instead of ID; Currently not possible as clients are from same host
					//clist->setSSL(ssl);
					printf("New user: cid = %d\n",cid);
					packet->ack = FAIL;
					if (cid) {
						packet->ack = SUCCESS;
						memcpy(packet->buffer,"New User Registered",20);
						packet->dst = cid;
					}
					else memcpy(packet->buffer,"New User Registration Failed",28);
					packet->dst = htonl(packet->dst);
					packet->src = htonl(getpid());
					//printf("New user id = %d, srv id = %x\n",packet->dst, packet->src);
					memcpy(reply,packet,sizeof(struct Packet));
				}
				break;

				case GET_ACTIVE_USER_LIST: //Get Active User List
				{
					int len  = 0;
					int  clientIP = ntohl(packet->src); //TODO: packet->src contains IP 
					//printf("client IP %d => ID %d\n",clientIP, this->clist->getClientID(clientIP));
					int clientID = this->clist->getClientID(clientIP);
					if(clientID == 0) {
						memset(packet->buffer,0,sizeof(packet->buffer));
						packet->ack = FAIL;
						packet->continued = 0;
						packet->dst = packet->src;
						packet->src = htonl(getpid());
						memcpy(reply,packet,sizeof(struct Packet));
						break;
					}
					char *data = this->clist->getClientList(clientID,len); /* Never returns data with a null */

					#ifdef DEBUG
					printf("\n\tClient List:");
					for(int i=0;i<len;i++) {
						printf("%x ",data[i]);
					}
					printf("\n");
					#endif
					while(len > (int)sizeof(packet->buffer)) 
					{
						#ifdef DEBUG
						printf("len = %d > buffer\n",len);
						#endif
						memset(packet->buffer,0,sizeof(packet->buffer));
						memcpy(packet->buffer,data,len);
						packet->ack = SUCCESS;
						packet->continued = 1;
						packet->dst = packet->src;
						packet->src = htonl(getpid());
						memcpy(reply,packet,sizeof(struct Packet));
						SSL_write(ssl, reply,sizeof(reply)); /* send reply */
						len -= sizeof(packet->buffer);
					}

					memset(packet->buffer,0,sizeof(packet->buffer));
					memcpy(packet->buffer,data,len);
					packet->ack = SUCCESS;
					packet->continued = 0;
					packet->dst = packet->src;
					packet->src = htonl(getpid());
					memcpy(reply,packet,sizeof(struct Packet));
					if(data) free(data);
				}
				break;

				case CALL_USER:
				{	/* Request from client for connecting to another client for communication */
					SSL *ssl1=0;
					X509 *cert1=0;
					printf("client ID = %x\n",packet->dst);
					int clientID = this->clist->getClientID(ntohl(packet->dst));
					printf("client ID = %x\n",clientID);
					if(!clientID)
						{if(logfd) fprintf(logfd, "Not registered client %d\n",ntohl(packet->dst));}
					else if((ssl1 = this->clist->getClientStream(clientID)) == 0)
						{ if(logfd) fprintf(logfd, "No Client SSL connection client %x\n",clientID);}
					else if ((cert1 = this->clist->getClientCertificate(clientID)) == 0)
						{if(logfd) fprintf(logfd, "No Client certificate client %x\n",packet->dst);}
					/* Check if client is not BUSY */
					if(clientID == 0 || ssl1 == 0 || cert1 == 0 || this->connectList->isConnected(clientID)) {
						if(logfd) fprintf(logfd,"client or ssl or cert is 0\n");
						memset(packet->buffer,0,sizeof(packet->buffer));
						packet->ack = FAIL;
						packet->continued = 0;
						packet->dst = packet->src;
						packet->src = htonl(getpid());
						memcpy(reply,packet,sizeof(struct Packet));
						break;
					}

						if(logfd) fprintf(logfd,"creating packet\n");
					struct Packet p;
					p.cmd = CALL_REQUEST;
					p.src = packet->src;
					p.dst = packet->dst;
					p.ack = SUCCESS;
					p.continued = 0;

					fprintf(stdout, "\n\tServer asking client %x for call receiving\n",p.dst);
					memcpy(msg,(void *)&p,sizeof(struct Packet));
					SSL_write(ssl1,msg,sizeof(msg));
				}
				continue;
					
				case CALL_REQUEST:
				{ /* Request for connecting to client for communication; when a clients want to communication to other client */
					SSL *ssl1 = 0;
					X509 *cert1 = 0;
					int clientID = this->clist->getClientID(ntohl(packet->dst));
					printf("client ID = %x\n",clientID);
					if(!clientID)
						fprintf(stdout,"Not registered client %d\n",ntohl(packet->dst));
					else if((ssl1 = this->clist->getClientStream(clientID)) == 0)
						printf("No Client SSL connection client %x\n",clientID);
					else if ((cert1 = this->clist->getClientCertificate(clientID)) == 0)
						printf("No Client certificate client %x\n",packet->dst);
					/* Check if client is not BUSY and request is sent */
					if(clientID == 0 || ssl1 == 0 || cert1 == 0) {
						memset(packet->buffer,0,sizeof(packet->buffer));
						packet->ack = FAIL;
						packet->continued = 0;
						packet->dst = packet->src;
						packet->src = htonl(getpid());
						memcpy(reply,packet,sizeof(struct Packet));
						break;
					}
					#ifdef DEBUG
					fprintf(stdout, "\n\tResponse %d bytes from callee::", bytes);
					for(int i = 0;i<100;i++)
						fprintf(stdout,"%02x ",buf[i]);
					fprintf(stdout,"\n");
					if(packet->ack == SUCCESS)
					fprintf(stdout, "\tCallee is ready to talk\n");
					#endif

					fprintf(stdout, "\n\tCallee is ready to talk %d -> %d",ntohl(packet->src),ntohl(packet->dst));
					packet->cmd = CALL_USER;
					memcpy(msg,packet,sizeof(struct Packet));
					SSL_write(ssl1,msg,sizeof(msg));
					this->connectList->startConnection(this->clist->getClientID(ntohl(packet->src)),this->clist->getClientID(ntohl(packet->dst)));
					continue;
				}

					break;
				case CALL_END: /* Disconnect the connection to the client; */
					if(this->connectList->hasConnection(this->clist->getClientID(ntohl(packet->src)),this->clist->getClientID(ntohl(packet->dst))))
						this->connectList->terminateConnection(this->clist->getClientID(ntohl(packet->src)),this->clist->getClientID(ntohl(packet->dst)));
				case DATA:
				{
					SSL *ssl1=0;
					int clientID = this->clist->getClientID(ntohl(packet->dst));
					if(!clientID)
						fprintf(stdout,"Not registered client %d\n",ntohl(packet->dst));
					else if((ssl1 = this->clist->getClientStream(clientID)) == 0)
						printf("No Client SSL connection client %x\n",clientID);
					/* Check if client is not BUSY and request is sent */
					if(clientID == 0 || ssl1 == 0) {
						memset(packet->buffer,0,sizeof(packet->buffer));
						packet->ack = FAIL;
						packet->continued = 0;
						packet->dst = packet->src;
						packet->src = htonl(getpid());
						memcpy(reply,packet,sizeof(struct Packet));
						break;
					}
					#ifdef DEBUG
					fprintf(stdout, "\nData: Reply message:%ld:",sizeof(buf));
					fflush(stdout);
					for(int i=0;i<100;i++) {
						//printf("%c ",reply[i]);
						fprintf(stdout, "%02x ",buf[i]);
					}
					fprintf(stdout, "\n");
					#endif
					SSL_write(ssl1, buf, sizeof(buf)); /* get request */
					continue;
				}
				break;
				case TERMINATE:
					strcpy(buf,"Terminate Session");
					sprintf(reply, echo,buf);   /* construct reply */
					buf[strlen(buf)] = 0;
					err = 5;
				break;

				default:
					buf[bytes] = 0;
					printf("Client msg: \"%s\"\n", buf);
					sprintf(reply, echo, buf);   /* construct reply */
				}
				printf("\nReply message:%ld:",sizeof(reply));
				for(int i=0;i<100;i++) {
					//printf("%c ",reply[i]);
					printf("%02x ",reply[i]);
				}
				printf("\n%d ",SSL_write(ssl, reply,sizeof(reply))); /* send reply */
			}
			else {
			    ERR_print_errors_fp(logfd);
				err++;
			}
		}
		delete packet;
	    }
	    sd = SSL_get_fd(ssl);       /* get socket connection */
	    SSL_free(ssl);         /* release SSL state */
	    close(sd);          /* close connection */

	    return 0;
	}

/** This function will accept the connection requests from the clients and 
 * create a thread for handling the packets received from the clients
 */
	int SSLServer::Accept() {
	    if( this->status != OPEN) {
		printf("Open the socket first\n");
		return -1;
	     }

	      struct sockaddr_in addr;
	      socklen_t len = sizeof(addr);
	      int client;//,*newSocket;

	      status = CONNECT;
	      while((client = accept(this->sd,(struct sockaddr*)&addr,&len)))
	      {
		if(logfd)fprintf(logfd,"Connection: %s:%d\n", inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));

		this->ssl = SSL_new(ctx);
		SSL_set_fd(this->ssl,client);

		//newSocket = (int *)calloc(1,sizeof(int));
		//*newSocket = client;
		if(pthread_create(&(this->thread),NULL,Servletfn,(void *)this)<0)
		{
		   perror("Cannot create thread");
	           exit(1);
		}
	      }
		return SUCCESS;
	}
