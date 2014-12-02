#include <stdio.h>
#include"aes.h"
#include "util.h"
#include<stdlib.h>

#include "encryptor.h"
	encryptor::encryptor() {
		//printf("Default constructor called \n");
		unsigned char hex_key_string[80] = {0x44,0x32,0x35,0x34,0x46,0x43,0x46,0x46,0x30,0x32,0x31,0x45,0x36,0x39,0x44,0x32,0x32,0x39,0x43,0x39,0x43,0x46,0x41,0x44,0x38,0x35,0x46,0x41,0x34,0x38,0x36,0x43};
		unsigned char key_str[40];//={0};
		memset(key_str,0,sizeof(key_str));
		int key_len = unhexify( key_str, (const char *)hex_key_string );
		memset(nonce_counter,0,16);//[0]=0;
		memset(stream_block,0,MAX_STREAM_SIZE*16);//[0]=0;
		send_offset=0;
		receive_offset = 0;
		aes_init( &ctx );
		
		set_key(key_str,key_len);
		precompute_keys();
	}
	encryptor::encryptor(/*unsigned char key_str[],*/int &key_len) {
		nonce_counter[0]=key_len;
		//if(!precompute_done) {
			//memset(nonce_counter,0,15);
			//for(int i=0;i<16;i++)
			//	nonce_counter[i]=0;
		    //memset( key, 0, 32 );
	/*	    printf("Init aes\n");
			fflush(stdout);
		    aes_init( &ctx );
		    printf("setkey\n");
			aes_setkey_enc( &ctx, key_str, key_len * 8 );
		    printf("crypt_ctr\n");
			for(int i=0;i<MAX_STREAM_SIZE;i++) {
				crypt_ctr( &ctx, nonce_counter, stream_block[i]);
			    for( i = 16; i > 0; i-- )
				if( ++nonce_counter[i - 1] != 0 )
				    break;
			}
		    printf("After crypt_ctr\n"); */
		//}
	//	precompute_done=1;
	}
	encryptor::~encryptor() {
		/* write key with random chars */
		aes_free(&ctx);
	}

	int encryptor::set_key(unsigned char key_str[], int key_len) {
		return aes_setkey_enc( &ctx, key_str, key_len * 8 );
	}

	int encryptor::precompute_keys() {
		for(int i=0;i<MAX_STREAM_SIZE;i++) {
		    crypt_ctr( &ctx, nonce_counter, stream_block[i]);
		    for(int j = 16; j > 0; j-- ) {
			if( (++nonce_counter[j - 1]) != 0 ) 
			    break;
		    }
		}
		return 0;
	}
	int encryptor::print_stream() {
		for(int i=MAX_STREAM_SIZE-100;i<MAX_STREAM_SIZE;i++) {
			printf("i:%d:",i);
			for(int j=0;j<16;j++)
				printf("%x ",stream_block[i][j]);
			printf("\n");
		}
		return 0;
	}
	int encryptor::crypt(unsigned char *io, int len, int send) {
		if(len & 0xF) {
			printf("Length not multiple of blocksize %d\n",len);
			return -1;
		}
		int *stream_offset;
		if(send) stream_offset = &send_offset;
		else stream_offset = &receive_offset;
		for(int i=0;i<len/16;i++) {
			for (int j=0;j<16;j++) {
				io[i*16+j] ^= stream_block[*stream_offset][j];
			}
			(*stream_offset)++;
			(*stream_offset) &= MAX_STREAM_SIZE;
		}
		return 0;
	}

	int encryptor::crypt_ctr( aes_context *ctx, unsigned char nonce_counter[16], unsigned char stream_block[16])
	{
	    //int i;
		memset((void *)stream_block,0,16);
	        aes_crypt_ecb( ctx, AES_ENCRYPT, nonce_counter, stream_block );
	    return( 0 );
	}
