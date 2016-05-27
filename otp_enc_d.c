/******************************************************************
 * Alex Rappa
 * CS 344
 * Program 4: OTP
 * Due: 3/12/2016
 * Description: This program will run in the background as a daemon. 
	 * Its function is to perform the actual One-Time Pad encoding. 
	 * This program will listen on a particular port, assigned when it 
	 * is first ran, and receives plaintext and a key via that port when a 
	 * connection to it is made. It will then write back the ciphertext to 
	 * the process that it is connected to via the same port. Note that the key 
	 * passed in must be at least as big as the plaintext. This program must output 
	 * an error if the program cannot be run due to a network error, such as the ports 
	* being unavailable.
******************************************************************/

#include <stdio.h>		//printf(), scanf()...
#include <unistd.h>		//close(), fork(), getpid(), read(), write(), dup2()...
#include <stdlib.h>
#include <fcntl.h>		//open(), fcntl()...
#include <time.h>		//rand()
#include <string.h>
#include <sys/types.h>	//pid_t
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>		//sigaction(),
#include <sys/socket.h>	//structs needed for sockets
#include <netinet/in.h>	//needed for internet domain addresses

#define BUFFER_SIZE	100000

/*	Prototypes	*/
void encrypt(int socketFD);

int main( int argc, char * argv[])
{
	//declare variables
	int sockfd, 		//server socket
		newsockfd, 		//new socket connected with client
		portno,			//port number server is listening on
		status,			//exit status of child processes
		n,				//character count from read(), write()
		numChild=0;		//number of child processes
	socklen_t clilen;	//stores size of the address of the client
	char buffer[BUFFER_SIZE];	//stores the read() and write() data
	struct sockaddr_in serv_addr,	//address of server
						cli_addr;	//address of client
	pid_t pid, 			//process id at fork()
		exitPid;		//pid returned from wait() in parent process
	
	//validate number of user arg: 'otp_enc_d port_number &'
	if (argc < 2) {
		fprintf(stderr,"ERROR, no port provided\n");
		exit(1);
	}
	else if(argc > 2)
	{
		fprintf(stderr,"ERROR, too many arguments provided\n");
		exit(1);
	}

	//create new socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	//(unix domain, stream socket, protocol->tcp)
	if (sockfd < 0) 							//returns -1 on failure
		error("ERROR opening socket");

	//zero out serv_addr
	bzero((char *) &serv_addr, sizeof(serv_addr));	//bzero() sets all values in a buffer to 0
	//assigner user port number
	portno = atoi(argv[1]);							//atoi() converts string of digits to an int
	
	//initialize serv_addr fields; (struct sockaddr_in)
	serv_addr.sin_family = AF_INET;					//AF_INET used for IP
	serv_addr.sin_addr.s_addr = INADDR_ANY;			//IP address of host
	serv_addr.sin_port = htons(portno);				//htons() converts port number to network byte order

	//bind the socket to an address: sockfd to serv_addr
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)	//bind(socket file descriptor, address, size of address)
		error("ERROR on binding");

	//listen on socket 'sockfd' for connections, max of 5
	listen(sockfd,5);
	clilen = sizeof(cli_addr);	//clilen is size of client address

	//process accepts new connections and forks a process to handle it
	while(1)
	{
		//check for completion of child processes
		int i;
		for(i=0; i < numChild; i++)
		{
			if(waitpid(-1, &status, WNOHANG) == -1)
				perror("wait failed");
			if(WIFEXITED(status))
				numChild -= 1;
		}
		
		newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr, &clilen);	//accept() returns new socket file descriptor
		if (newsockfd < 0) 
			error("ERROR on accept");
		
		//fork new process
		pid = fork();
		
		//error occurred
		if(pid < 0)
			error("ERROR on fork");
		//Child process
		else if(pid == 0)
		{
			close(sockfd);			//close server socket
			encrypt(newsockfd);		//call encrypt, passing new socket file descriptor
			exit(0);				//child exits
		}
		//Parent process
		else
		{
			numChild += 1;		//increment number of child processes
			close(newsockfd);	//close new socket
		}
	}

	return 0;
}


/********************* encrypt() *********************
* This function takes a socket file descriptor and:
*	1) Reads client plain text data
*	2) Encrypts data using a One-Time-Pad encryption
*	3) Writes ciphertext data back to the client
 *****************************************************/
void encrypt(int newsockfd)
{
	int n=0, m=0, i=0, size=0, rbytes=0;
	char p_buffer[BUFFER_SIZE];	//store plaintext
	char k_buffer[BUFFER_SIZE];	//store key
	char c_buffer[BUFFER_SIZE];	//stores cyphertext
	char procName[50];
	char accept[] = "accept";
	char reject[] = "reject";
	
	//PROCESS NAME: read client data
	n = recv(newsockfd, procName, sizeof(procName), 0);
	if (n < 0) error("ERROR reading from socket");	
	//check process name
	if(strncmp(procName, "otp_enc", 7) == 0)
	{
		n = write(newsockfd, accept, strlen(accept));
		if (n < 0) error("ERROR writing to socket");		
	}
	else //a process other than 'otp_enc' is sent a rejection message & this process returns to close socket
	{
		n = write(newsockfd, reject, strlen(reject));
		if (n < 0) error("ERROR writing to socket");
		return;
	}
	
	//FILE SIZE: read client data
	n = recv(newsockfd, &size, sizeof(size), 0);
	if (n < 0) error("ERROR reading from socket");	
	
	//PLAINTEXT: read client data from socket
	bzero(p_buffer,BUFFER_SIZE);	//zero out buffer

	do
	{
		n = recv(newsockfd, p_buffer, size, 0);						//read() blocks until there's something to read (after client executes write())
		if (n < 0) error("ERROR reading from socket");		//read() returns number of characters read >> n
		rbytes += n;
	}while(rbytes < size);
	
	//KEY: read client data from socket
	bzero(k_buffer,BUFFER_SIZE);	//zero out buffer
	rbytes=0;

	do
	{
		m = recv(newsockfd, k_buffer, size, 0);						//read() blocks until there's something to read (after client executes write())
		if (m < 0) error("ERROR reading from socket");		//read() returns number of characters read >> n
		rbytes += m;
	}while(rbytes < size);
	
//printf("host>p>%i\n", strlen(p_buffer));
//printf("host>k>%i\n", strlen(k_buffer));
//printf("host>k>%s\n", k_buffer);
	
	/*	ENCRYPT	*/
	bzero(c_buffer,BUFFER_SIZE);
	for(i=0; i < size; i++)		//n is number of char (bytes) read in from the plaintext file
	{		
		
		//A-Z is 0-26, space = 27 *** ASCII A-Z is 65-90, 91 -> we change to 32='space'
		int x = (int)p_buffer[i];
		if(x == 32)
			x=91;

		x -= 65;
		int y = (int)k_buffer[i];
		if(y == 32)
			y=91;

		y -= 65;
		
		int r = ((x+y)%27);
		r += 65;
		
		if(r == 91)
			r=32;
		char l = (char)r;
		c_buffer[i] = l;
	}

	//printf("p >%s\n", p_buffer);
	//printf("k >%s\n", k_buffer);
	//printf("c >%s\n", c_buffer);
	//CIPHERTEXT: send encrypted text back to client
	n = write(newsockfd, c_buffer, strlen(c_buffer));
	if (n < 0) error("ERROR writing to socket");
	
	return;
}