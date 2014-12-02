/*! \file DHGenerator.h
\brief A Documented file.Contains the list of functions required for DH Parameter generation.
*/


#include <stdio.h> 
#include <stdlib.h>
#include <gmp.h>

class DHGenerator{

	mpz_t n;
	mpz_t g;
	mpz_t a; // random
	mpz_t x; // generated
	mpz_t y; // received
	mpz_t key;




public:
	/*! \fn DHGenerator()
 	\brief Default Constructor for the class DHGenerator
	*/
	DHGenerator();

	/*! \fn DHGenerator(unsigned char *keyPart,int length)
	\brief Constructor for the class DHGenerator. Need to call this contructor when the other party has initiated the DH Generation
	\param keyPart The partial key required to generate DH Session Key
	\param length The length of the partial key
	*/
	DHGenerator(unsigned char *keyPart,int length);

	/*! \fn ~DHGenerator()
 	\brief The default destructor of the class DHGenerator
	*/
	~DHGenerator();

	/*! \fn void generateRandomNumber()
 	\brief Generates random number of 64 bits
	*/
	void generateRandomNumber();

	/*! \fn void generatePartialKey()
	\brief Generates Partial Key which is required by the other user
	*/
	void generatePartialKey();

	/*! void getPartialKey(unsigned char *partKey,size_t length)
	\brief Returns the partial key generated.
	\param partKey The partial key required send to the other client
	\param length The length of the partial key
	*/
	void getPartialKey(unsigned char *,size_t );


	/*! void generateSessionKey(unsigned char *partKey,unsigned int length)
 	\brief Generates Session Key based on partial key received from other client
	\param partKey The partial key from the other client
	\param length The length of the partial key
	*/	
	void generateSessionKey(unsigned char *,unsigned int );

	/*! void setPartialKey(unsigned char *partKey,int length)
 	\brief Sets the Partial Key as recieved from the other client
	\param partKey The partial key from the other client
	\param length The length of the partial key
	*/
	void setPartialKey(unsigned char *,int );

	/*! void generateSessionKey()
 	\brief Generates the Session Key
	*/
	void generateSessionKey();

	/*! void getSessionKey(unsigned char *sessionKey,size_t length)
 	\brief Returns the generated session key
	\param sessionKey Session Key generated
	\param Length of the session key
	*/
	void getSessionKey(unsigned char *sessionKey,size_t length);

	/*! unsigned long int randomSeed()
 	\brief Returns 4 bytes of randomSeed
	*/
	unsigned long int randomSeed();

};
