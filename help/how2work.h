/* It's not done now */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#ifndef HOW2WORK_H

struct ports
{
	const char *ip[5];
	const char *rmthost[5];
};

struct byte
{
	char *msg[1000];
	char *dec[1000];
};

struct http
{
	char *reqtype[20];
}

int server(int port)
{
	int server_fd, new_socket, valueread;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char buffer[1024] = {0};
	char *hello = "Connected to vpn";

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("Can't connected to vpn");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))

	{
		perror("Can't connected to vpn");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);

	// Forcefully attaching socket to the port 8080

	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)

	{
		perror("Can't connected to vpn");
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, 3) < 0)
	{
		perror("Can't connected to vpn");
		exit(EXIT_FAILURE);
	}

	if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
	{
		perror("Can't connected to vpn");
		exit(EXIT_FAILURE);
	}

	valueread = read(new_socket, buffer, 1024);

	printf("%s\n", buffer);

	send(new_socket, hello, strlen(hello), 0);

	printf("Server running now\n");

	return 0;
}


int client(int ip, int port, int targetip)
{
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	char *hello = "Hello vpn";
	char buffer[1024] = {0};
	
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
{ 
        printf("\n Can't connected to vpn' \n"); 
		return -1; 
} 
	serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
    
    // Convert IPv4 and IPv6 addresses from text to binary form 

    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
} 

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
{ 
        printf("\nConnection Failed to vpn \n"); 
        return -1; 
    } 
    send(sock , hello , strlen(hello) , 0 ); 
    printf("Connected\n"); 
    valread = read( sock , buffer, 1024); 
    printf("%s\n",buffer ); 
	
	return 0; 
}
#endif

/* Source code of socket: https://www.geeksforgeeks.org/socket-programming-cc/amp/*/