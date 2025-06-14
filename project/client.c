#include "consts.h"
#include "security.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <errno.h>

void hostname_to_ip(const char* hostname, char* ip) {
    struct hostent* he;
    struct in_addr** addr_list;

    if ((he = gethostbyname(hostname)) == NULL) {
        fprintf(stderr, "Error: Invalid hostname\n");
        exit(255);
    }

    addr_list = (struct in_addr**) he->h_addr_list;

    for (int i = 0; addr_list[i] != NULL; i++) {
        strcpy(ip, inet_ntoa(*addr_list[i]));
        return;
    }

    fprintf(stderr, "Error: Invalid hostname\n");
    exit(255);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: client <hostname> <port> \n");
        exit(1);
    }

    /* Create sockets */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // use IPv4  use UDP

    /* Construct server address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET; // use IPv4
    char addr[100] = {0};
    hostname_to_ip(argv[1], addr);
    server_addr.sin_addr.s_addr = inet_addr(addr);
    // Set sending port
    int PORT = atoi(argv[2]);
    server_addr.sin_port = htons(PORT); // Big endian

    init_sec(CLIENT_CLIENT_HELLO_SEND, argv[1], argc > 3);
    // Connect to server
    // connect()
    connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (sockfd < 0) {
        fprintf(stderr, "Error: Could not connect to server\n");
        exit(255);
    }

    // Set the socket nonblocking
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int) {1}, sizeof(int));

    uint8_t send_buf[1024];
    ssize_t send_len = input_sec(send_buf, sizeof(send_buf));

    if (send_len > 0) {
        if (send(sockfd, send_buf, send_len, 0) < 0) {
            fprintf(stderr, "Error: Could not send Client Hello message\n");
            close(sockfd);
            exit(255);
        }
        printf("Client Hello message sent\n");
    } else {
        fprintf(stderr, "Error: Failed to generate Client Hello message\n");
        close(sockfd);
        exit(255);
    }

    uint8_t client_buf[1024];

    while(1) {
        int bytes_recvd = recv(sockfd, client_buf, sizeof(client_buf), 0);
        if (bytes_recvd > 0) {
            output_sec(client_buf, bytes_recvd);
        }
        ssize_t send_len = input_sec(send_buf, sizeof(send_buf));
        // send data
    }
    close(sockfd);
    return 0;
}
