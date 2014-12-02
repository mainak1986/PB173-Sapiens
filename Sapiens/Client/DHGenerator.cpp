/*
 * DHGenerator.cpp
 *
 *  Created on: Dec 1, 2014
 *      Author: mainak
 */

#include "DHGenerator.h"

/* Function to generate 4 byte random seed. The return value is generated using /dev/urandom */
unsigned long int DHGenerator::randomSeed()
{
  unsigned long int random;
  FILE *fp;
  int i;

  if((fp=fopen("/dev/urandom","r"))==NULL) // opens /dev/urandom to read random numbers
   exit(1);

  random = 0x0;

  for(i = 0;i<4;i++)
  {
    random =  random|fgetc(fp); //reads random number

    if(i!=3)
     random = random << 8; //except the last byte left shift the data by 8 bits
  }

  fclose(fp);

  return random;
}

DHGenerator::DHGenerator()
{
	printf("\n\t%d %s",__LINE__,__FILE__);

	mpz_init(n);
	mpz_init(g);
	mpz_init(x);
	mpz_init(a);
	mpz_init(y);
	mpz_init(key);

	mpz_set_str (n,"9627533057541626274",10); // setting n to a large prime number
	mpz_set_ui(g,5); // setting generator g as 5

	printf("\n\t%d %s",__LINE__,__FILE__);
}


DHGenerator::DHGenerator(unsigned char *y,int length)
{

	DHGenerator();

	mpz_import (this->y,length, 1, sizeof(y[0]), 0, 0, y);
}

DHGenerator::~DHGenerator()
{
	mpz_clear(n);
	mpz_clear(g);
	mpz_clear(x);
	mpz_clear(a);
	mpz_clear(y);
	mpz_clear(key);
}

void DHGenerator::setPartialKey(unsigned char *y,int length)
{
	mpz_import (this->y,length, 1, sizeof(y[0]), 0, 0, y);
}


void DHGenerator::generateRandomNumber()
{

	gmp_randstate_t rstate;

	gmp_randinit_mt(rstate);

	do
	{
		gmp_randseed_ui(rstate,randomSeed());

		do{
			mpz_urandomb(a,rstate,64); // generate random number p less than 2^64-1

		}while(mpz_sizeinbase(a,2)!=64); //checks whether p is 64 bit or not


	}while(!mpz_cmp (n,a));

	gmp_printf("\n\tValue of a::%Zd \n\n\t",a);


	return;
}


void DHGenerator::generatePartialKey()
{
	generateRandomNumber();

	printf("\n\tIn generate random function");

	mpz_powm (x,g,a,n);

	return;
}


void DHGenerator::getPartialKey(unsigned char *key,size_t length)
{
	printf("\n\tIn get partial key");

	mpz_export((void *)key,&length,1,1,0,0,this->x);

	for(int  i = 0;i<length;i++)
		printf("%02x ",*(key+i));

	return;
}


void DHGenerator::generateSessionKey(unsigned char *y,unsigned int length)
{
	mpz_import (this->y,length, 1, sizeof(y[0]), 0, 0, y);

	mpz_powm(key,this->y,a,n);

	printf("\n\tSession key generated");

	return;
}


void DHGenerator::generateSessionKey()
{
	mpz_powm (key,y,a,n);

	printf("\n\tSession key generated");

	return;
}

void DHGenerator::getSessionKey(unsigned char *sessionKey,size_t length)
{
	mpz_export((void *)sessionKey,&length,1,1,0,0,this->key);

	return;
}



