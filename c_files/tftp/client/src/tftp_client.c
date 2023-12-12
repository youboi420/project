#include "../includes/headers.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char const *argv[])
{
    /* code */
    char packet[PACKET_SIZE + 1] = "\0", prev_packet[PACKET_SIZE] = "\0", filename[STR_FILE_LIMIT] = "\0", mode[STR_FILE_LIMIT] = "\0", err_msg[PACKET_DATA_SIZE] = "\0", port[PORT_LEN] = "\0", ip[INET_ADDRSTRLEN + 1];
	unsigned short blockno = 1, timeout_cnter = 0, potential_err, op_code = OP_END;
	struct sockaddr_in server_s, client_s;
	int packet_size = PACKET_DATA_SIZE, client_sock, flag = 0, connection, write_count = -1;
	socklen_t len;
	ssize_t n;
	FILE *file = NULL;

    /* usage ./client ip port mode file  */
    if (argc != 5)
    {
        error("Incorrect number of parameters");
        usage();
        exit_prog("");
    }

    client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (check_error(client_sock)) exit_prog("sock asign failed");
    
    memset(&client_s, 0, sizeof(client_s));
    
    check_args(argv);

    strcpy(ip, argv[1]); /* get the port into the port array */
    strcpy(port, argv[2]); /* get the port into the port array */
    strcpy(mode, argv[3]);
    strcpy(filename, argv[4]);

    server_s.sin_family = AF_INET;
    server_s.sin_addr.s_addr = inet_addr(ip);
    server_s.sin_port = htons(atoi(port));


    
    return EXIT_SUCCESS;
}

void usage(void)
{
    printf("Usage: ./client <ip> <port> <mode> <file>\n\n");
    printf("Description:\n");
    printf("  Connects to a server using TCP/IP and performs a specified operation.\n\n");
    printf("Arguments:\n");
    printf("  <ip>      : IP address of the server.\n");
    printf("  <port>    : Port number to establish the connection.\n");
    printf("  <mode>    : Operation mode (e.g., 'upload', 'download').\n");
    printf("  <file>    : File to be transferred or processed.\n\n");
    printf("Example:\n");
    printf("  ./client 192.168.1.100 8080 ascii data.txt\n");
    printf("  ./client server.example.com 12345 binary result.txt\n");
}

void check_args(const char *argv[])
{
    int p = atoi(argv[2]);

    if (strlen(argv[1]) != INET_ADDRSTRLEN)
        exit_prog("invalid ip address");

    if (strlen(argv[2]) != PORT_LEN || (p < MIN_PORT || p > MAX_PORT))
        exit_prog("invalid port number");

    if (strcmp(argv[3], "binary") != 0 && strcmp(argv[3], "ascii") != 0) /* if mode is not binary or ascii */
        exit_prog("invalid mode");

    if (strchr(argv[4], '/') != 0)
        exit_prog("invalid file name");
}