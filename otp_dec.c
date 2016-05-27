/******************************************************************
 * Alex Rappa
 * CS 344
 * Program 4: OTP
 * Due: 3/12/2016
 * Description: Similarly, this program will connect to otp_dec_d 
	 * and will ask it to decrypt ciphertext using a passed-in ciphertext 
	 * and key. It will use the same syntax and usage as otp_enc, and must 
	 * be runnable in the same three ways. otp_dec should NOT be able to 
	 * connect to otp_enc_d, even if it tries to connect on the correct 
	 * port - you'll need to have the programs reject each other.
******************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 		//struct hostnet

#define BUFFER_SIZE	100000

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{
	//declare variables
	FILE * fptr;
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[BUFFER_SIZE];
	int size;
	//arg[1] contains plaintext file name
	//arg[2] contains key file name
	//arg[3] contains port number
	
	//validate number of user arg
    if (argc < 4) {
       fprintf(stderr,"ERROR Syntax: otp_enc plaintext key port\n");
       exit(0);
    }
	
	//create new socket
    portno = atoi(argv[3]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
	
	//fill (struct hostnet*) server with server info
    server = gethostbyname("localhost");
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
	
	//initialize fields serv_addr: (struct sockaddr_in)
    bzero((char *) &serv_addr, sizeof(serv_addr));	//zero out serv_addr
    serv_addr.sin_family = AF_INET;					//AF_INET used for IP
	//bcopy(char* s1, char* s2, length) copies 'length' bytes from 's1' to 's2'
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);	//server->h_addr is the IP address of the server
    serv_addr.sin_port = htons(portno);		//port number of host

	//connect to server
	//connect(socket file descriptor, address of host, size of address)
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) //returns 0 upon success, -1 upon failure
	{
		char errmsg[100];
		snprintf(errmsg, 100, "Error: could not contact otp_dec_d on port %i", portno);
		error(errmsg);
		exit(2);
	}
	
	//write to host: our process name 
	char procName[] = "otp_dec";
	n = write(sockfd, procName, strlen(procName));
	if (n < 0) error("ERROR writing to socket");

	//read from host
	char hostReply[50];
	n = recv(sockfd, hostReply, sizeof(hostReply), 0);
	if (n < 0) error("ERROR reading from socket");	

	//check host reply
	if(strncmp(hostReply, "reject", 6) == 0)	//if reject, send error message and exit(1)
	{
		char errmsg[100];
		snprintf(errmsg, 100, "ERROR: otp_dec denied connection to otp_enc_d on port %i", portno);
		error(errmsg);
		exit(1);
	}
	
	/*	Open and send CIPHEREXT file string to otp_dec_d	*/
	fptr = fopen(argv[1], "r");

	//if successful open
	if(fptr)
	{
		bzero(buffer, BUFFER_SIZE);			//zero out buffer
		fgets(buffer, BUFFER_SIZE-1, fptr);	//get line from file
		if(buffer)
		{
			strtok(buffer, "\n");			//removes "\n"
			size = strlen(buffer);
			
			/*	INPUT VALIDATION	*/
			int i;
			for(i=0; i < size; i++)
			{
				//validate plain text characters
				if(buffer[i] == ' ') {} //do nothing, spaces are allowed
				else if(buffer[i] < 'A' || buffer[i] > 'Z')		
				{
					//printf("Bad character at buffer[%i] = %c\n", i, buffer[i]);
					error("otp_dec error: input contains bad characters, exiting");
					exit(1);
				}
			}
			
			//write to host: SIZE
			n = write(sockfd, &size, sizeof(size));
			if (n < 0) error("ERROR writing to socket");	
			
			//write to host: BUFFER 
			n = write(sockfd, buffer, strlen(buffer));
			if (n < 0) error("ERROR writing to socket");			
		}
		
		//close file pointer
		fclose(fptr);
	}
	else {error("ERROR unable to open file");}

	/*	Open and send KEY file string to otp_enc_d	*/
	fptr = fopen(argv[2], "r");

	//if successful open
	if(fptr)
	{
		bzero(buffer, BUFFER_SIZE);			//zero out buffer
		fgets(buffer, size+1, fptr);	//get line from file: only need same # of char's from key as in plaintext so we read up to 'size'
		if(buffer)
		{
			strtok(buffer, "\n");			//removes "\n"

			//validate key > ciphertext
			if(strlen(buffer) < size)
			{
				error("ERROR: key is too short, exiting");
				exit(1);
			}
			
			/*	INPUT VALIDATION	*/
			int i;
			for(i=0; i < size; i++)
			{
				//validate key characters
				if(buffer[i] == ' ') {} //do nothing, spaces are allowed
				else if(buffer[i] < 'A' || buffer[i] > 'Z')		
				{
					//printf("Bad character at key[%i] = %c\n", i, buffer[i]);
					error("otp_enc error: key contains bad characters, exiting");
					exit(1);
				}
			}
			
			//write to host: BUFFER 
			n = write(sockfd, buffer, strlen(buffer));
			if (n < 0) error("ERROR writing to socket");			
		}
		
		//close file pointer
		fclose(fptr);
	}
	else {error("ERROR unable to open file");}
	
	bzero(buffer,BUFFER_SIZE);

	//read from host
	int rbytes=0;
    do
	{
		n = recv(sockfd, buffer, BUFFER_SIZE, 0);
		if (n < 0) error("ERROR reading from socket");
		rbytes += n;
	}while(rbytes < size);
	
	printf("%s\n", buffer);
	
	//close socket
    close(sockfd);

	//exit
    return 0;
}