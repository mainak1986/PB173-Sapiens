#ifndef __PACKET_H
#define __PACKET_H

#define PACKETSIZE 1024

struct Packet{

	unsigned char cmd;
	unsigned char ack;
	unsigned char continued;
	unsigned char pad;
	unsigned int src;
	unsigned int dst;
	short len;
	short pad2;
	unsigned char buffer[PACKETSIZE - (sizeof(unsigned int)*4)];
};
#endif
