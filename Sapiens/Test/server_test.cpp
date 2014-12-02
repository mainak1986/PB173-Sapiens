#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
#include<sys/stat.h>

TEST_CASE( "Encrypt Hash File not exists", "[encrypt hash]" ) {
	int c=5;
	char *v[255]={ENCRYPT,"donotexists.txt","inx.out",KEY1,IV1};
    REQUIRE( (encrypt_main(c,(char **)v) == 1));
}
