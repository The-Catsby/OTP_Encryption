/* Alex Rappa
 * CS 344
 * Program 4: OTP - Keygen.c
 * Description: This program creates a key file of specified length. 
	* The characters in the file generated will be any of the 27 allowed characters
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h> 
#include <string.h>

int main( int argc, char * argv[])
{
	//validate number of user args
	if (argc < 2) {
		fprintf(stderr,"ERROR, no number provided\n");
		exit(1);
	}
	
	//seed random
	time_t myTime; 
	myTime = time(NULL);
	srand((unsigned)myTime);	
	
	int n = atoi(argv[1]);	//converts string to int

	//printf("Random letters:");
	int i;
	for(i=0; i<n; i++)
	{
		//A-Z is 65-90; space is 32
		int r = (rand()%27) + 65;	//rand # 0-26 + 65 = 65-91
		if(r == 91)
			r = 32;			//if r is 91='[' change to 32='Space'
		char l = r;	
		printf("%c", l);
	}
	printf("\n");
	return;
}