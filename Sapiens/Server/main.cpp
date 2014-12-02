#include"server.h"
SSLServer* server;
void close_server();

int main(int argc,char *argv[])
{   
	int portnum=5000;
	if(argc > 1)
		portnum = atoi(argv[1]);
	//SSLServer server(atoi(portnum));
	server = new SSLServer();
	server->setport(portnum);

        char CertFile[] = "server.crt";
        char KeyFile[] = "serverkey.pem";

	atexit(close_server);
	server->setpassword("pb173"); /* load certs */
	server->LoadCertificates(CertFile, KeyFile); /* load certs */
	//server->LoadCertificates();
	server->Open();    /* create server socket */
	server->Accept();
}

void close_server()
{
	delete server;

}
