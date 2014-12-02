#ifndef __ENCRYPTOR_H
#define __ENCRYPTOR_H

#include <stdio.h>
#include"aes.h"
#include<stdlib.h>

/* Note: Max stream size must be power of 2 */
#define MAX_STREAM_SIZE 1024*256
class encryptor{
	//int precompute_done;
	aes_context ctx;
	unsigned char stream_block[MAX_STREAM_SIZE][16];
	unsigned char nonce_counter[16];
	int send_offset;
	int receive_offset;

public:
	encryptor() ;
	encryptor(/*unsigned char key_str[],*/int &key_len) ;
	~encryptor();

	int set_key(unsigned char key_str[], int key_len) ;

	int precompute_keys() ;
	int print_stream() ;
	int crypt(unsigned char *io, int len, int send) ;
	int crypt_ctr( aes_context *ctx, unsigned char nonce_counter[16], unsigned char stream_block[16]);
};

#endif
