#include "../includes/headers.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int main(int argc, char const *argv[])
{
    /* code */
    char packet_to_send[PACKET_SIZE + 1] = "\0", packet_to_recv[PACKET_SIZE + 1] = "\0" ,prev_packet[PACKET_SIZE] = "\0", filename[STR_FILE_LIMIT] = "\0", mode[STR_FILE_LIMIT] = "\0", err_msg[PACKET_DATA_SIZE] = "\0", port[PORT_LEN] = "\0", ip[INET_ADDRSTRLEN + 1],  operation[PACKET_HEAD] = "\0";
	unsigned short blockno = 0, blockno_echo = 0, client_blockno = 0 ,timeout_cnter = 0, potential_err, op_code = OP_END;
	struct sockaddr_in server_s, client_s;
	int packet_size = PACKET_DATA_SIZE, client_sock, flag = 1, connection, write_count = -1;
	socklen_t len;
	ssize_t n;
	FILE *file_ptr = NULL;

    /* usage ./client ip port mode file  */
    if (argc != 6)
    {
        usage();
        exit_prog("Incorrect number of parameters");
    }

    handle_args(argv, ip, port, mode, filename, operation);

    // okay("ip:%s:%s | mode: %s | fnm:%s | op:%s", ip, port, mode, filename, operation);
    // exit(EXIT_SUCCESS);

    client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (check_error(client_sock)) exit_prog("sock asign failed");
    
    memset(&client_s, 0, sizeof(client_s));
    server_s.sin_family = AF_INET;
    server_s.sin_addr.s_addr = inet_addr(ip);
    server_s.sin_port = htons(atoi(port));
    
    if (strcmp(operation, "get") == 0)
    {
        okay("mode get");
        /* the function  initilize the first packet to send for the read request */
        n = prep_packet(filename, mode, packet_to_send, OP_RRQ);
        flag = sendto(client_sock, packet_to_send, (size_t)(n), 0, (struct sockaddr*)&server_s, sizeof(server_s));
        
        memset(packet_to_send, 0, sizeof(packet_to_send));
        if (check_error(flag)) exit_prog("packet failed to send");
        get_local_mode(mode, OP_RRQ);
        file_ptr = open_file(filename, mode); /* opening file to write file from server */
        if (!file_ptr) exit_prog("given file is invalid");
        /* check op code for failure */
        while(packet_size == PACKET_DATA_SIZE) /* if we reached the EOF */
        {
            len = (socklen_t)sizeof(server_s);
            n = recvfrom(client_sock, packet_to_recv, sizeof(packet_to_recv), 0, (struct sockaddr *)&server_s, &len);
            packet_to_recv[n] = '\0';
            op_code = packet_to_recv[1];
            okay("got op code %hu", op_code);/* check op code for failure */
            switch (op_code)
            {
                case OP_ERROR:
                    error("[%s]", (&packet_to_recv[PACKET_HEAD]));
                    exit_prog("transfer failed");
                    break;
        
                case OP_ACK:
                    okay("got ack not writing");
                    break;

                default:
                    packet_size = handle_rrq_packet(packet_to_recv, &blockno, file_ptr, n - PACKET_HEAD);
                    break;
            }
            if (check_error(n)) exit_prog("recv failed");

            prepare_ack_packet(blockno, packet_to_send);
            if (check_error(sendto(client_sock, packet_to_send, (size_t)(PACKET_HEAD),0 ,(struct sockaddr *) &server_s, len))) exit_prog("send ack failed");
            blockno++;
        }
        fclose(file_ptr);
        okay("Got file %s, successfully!", filename);
    }
    else if (strcmp(operation, "put") == 0)
    {
        okay("mode put");
        /* 
            the function will verify if theres such file and if so 
            it will initilize the first packet to send
        */
        n = prep_packet(filename, mode, packet_to_send, OP_WRQ);
        flag = sendto(client_sock, packet_to_send, (size_t)(n), 0, (struct sockaddr*)&server_s, sizeof(server_s));
        if (check_error(flag)) exit_prog("packet failed to send");
        memset(packet_to_send, 0, sizeof(packet_to_send));
        get_local_mode(mode, OP_WRQ);
        file_ptr = open_file(filename, mode);
        if (!file_ptr)
        {
            packet_to_send[0] = 0;
            packet_to_send[1] = OP_ERROR;
            packet_to_send[2] = 0;
            packet_to_send[3] = FILE_ERR;
            strcpy(&packet_to_send[PACKET_HEAD],"[-] file error");
            flag = sendto(client_sock, packet_to_send, (size_t)(n), 0, (struct sockaddr*)&server_s, sizeof(server_s));
            if (check_error(flag)) exit_prog("send failed");
            exit_prog("given file is invalid");
        }
        else
        {
            okay("getting first ack echo");
            flag = recvfrom(client_sock, packet_to_recv, sizeof(packet_to_recv), 0, (struct sockaddr *)&server_s, &len);
            if (check_error(flag)) exit_prog("recv from failed"); 
            if (packet_to_recv[1] == OP_ERROR)
            {
                error("[%s]", &packet_to_recv[PACKET_HEAD]);
                exit_prog("server send op code error");
            }
            blockno++;
        }

        while (1)
        {
            n = prepare_data_packet(blockno,  file_ptr, packet_to_send);
            /* send file */
            flag = sendto(client_sock, packet_to_send, (size_t)(n + PACKET_HEAD), 0, (struct sockaddr *)&server_s, sizeof(server_s));
            if (check_error(flag)) exit_prog("send failed");
            
            /* process ack */
            flag = recvfrom(client_sock, packet_to_recv, sizeof(packet_to_recv), 0, (struct sockaddr *)&server_s, &len);
            if (check_error(flag)) exit_prog("recv from failed");
            op_code = packet_to_recv[1];
            switch (op_code)
            {
                case OP_ERROR:
                    error("[%s]", &packet_to_recv[PACKET_HEAD]);
                    exit_prog("server send op code error");
                    break;
                default:
                    /* ack */
                    if (is_block_num_ack(packet_to_recv, blockno)) blockno++;
                    else
                    {
                        /* resend the packet and continue */
                        // while(!(is_block_num_ack(packet_to_recv, blockno)))
                        // {
                            error("reseding");
                            flag = sendto(client_sock, packet_to_send, (size_t)(n + PACKET_HEAD), 0, (struct sockaddr *)&server_s, sizeof(server_s));
                            if (check_error(flag)) exit_prog("send failed");
                            flag = recvfrom(client_sock, packet_to_recv, sizeof(packet_to_recv), 0, (struct sockaddr *)&server_s, &len);
                            if (check_error(flag)) exit_prog("recv from failed");
                        // }
                        timeout_cnter++;
                    }
                    if (timeout_cnter >= TIMEOUT_LIMIT)
                    {
                        exit_prog("transfred failed reached-timeout-limit");
                    }
                    break;
            }
            if (n < PACKET_DATA_SIZE)
            {
                okay("Reached EOF");
                break;
            }
            /* dont forget to blockno++ if the packet is OP_ACK and i_blk_n_ack() */
            /* check if acked. if so inc by 1 else. resend the packet. and inc timeout_counter by 1 */
        }
    }
    else
    {
        exit_prog("invalid type of request");
    }
    return EXIT_SUCCESS;
}

void usage(void)
{
    printf("Usage: ./client <ip> <port> <request> <mode> <file>\n\n");
    printf("Description:\n");
    printf("  Connects to a server using TCP/IP and performs a specified operation.\n\n");
    printf("Arguments:\n");
    printf("  <ip>      : IP address of the server.\n");
    printf("  <port>    : Port number to establish the connection.\n");
    printf("  <request> : The type of the request (put/get).\n");
    printf("  <mode>    : Operation mode (e.g., 'upload', 'download').\n");
    printf("  <file>    : File to be transferred or processed.\n\n");
    printf("Example:\n");
    printf("  ./client 192.168.1.100 8080 get netascii data.txt\n");
    printf("  ./client server.example.com 12345 put octet result.bin\n");
}

void handle_args(const char *argv[], char ip[], char port[], char mode[], char filename[], char operation[])
{
    int p = atoi(argv[2]);

    if (strlen(argv[1]) > INET_ADDRSTRLEN || strlen(argv[1]) < 8)
        exit_prog("invalid ip address");

    if ((p < MIN_PORT || p > MAX_PORT))
        exit_prog("invalid port number");

    if (strlen(argv[3]) != PACKET_HEAD - 1)
        exit_prog("invalid mode");

    // if ((strcmp(argv[4], "binary") == 0 || strcmp(argv[3], "ascii") == 0)) /* if mode is not binary or ascii */
    // {
    //     exit_prog("???");
    // }
    // else
    //     error("invalid mode [%s]\t%i,%i, %i", argv[4], strcmp(argv[4], "binary"), strcmp(argv[4], "ascii"), !(strcmp(argv[4], "binary") == 0 || strcmp(argv[3], "ascii") == 0));
    if (strchr(argv[5], '/') != 0)
        exit_prog("invalid file name");

    /* if these execute it means that the input is valid */
    strcpy(ip, argv[1]); /* get the port into the port array */
    strcpy(port, argv[2]); /* get the port into the port array */
    strcpy(operation, argv[3]); /* get the type of request (get/put) */
    strcpy(mode, argv[4]); /* get the the type of the file (ascii/octet) */
    strcpy(filename, argv[5]); /* get the filename */
}

void get_local_mode(char *mode, int op)
{
    if (op == OP_RRQ)
    {
        if (strcmp(mode, "netascii") == 0) strcpy(mode, "w");
        else if (strcmp(mode, "octet") == 0) strcpy(mode, "wb");
    }
    else if (op == OP_WRQ)
    {
        if (strcmp(mode, "netascii") == 0) strcpy(mode, "r");
        else if (strcmp(mode, "octet") == 0) strcpy(mode, "rb");
    }
}

void exit_prog(char err_msg[])
{
	error("{%s}\n", err_msg);
	exit(EXIT_FAILURE);
}

void prepare_ack_packet(unsigned short blockno, char packet[])
{
    char one = blockno >> 8;
    char two = blockno;

    packet[0] = 0;
    packet[1] = OP_ACK;
    packet[2] = one;
    packet[3] = two;
}

int prep_packet(char *filename, char *mode, char *packet_ts, int op)
{
    int i = 0;

    packet_ts[i++] = 0;
    packet_ts[i++] = op;
    // strcpy filename to packet
    strcpy(packet_ts + i, filename);
    i += strlen(filename) + 1;
    // strcpy mode to packet_ts
    strcpy(packet_ts + i, mode);
    i += strlen(mode) + 1;
    // null termination
    packet_ts[i] = '\0';
    /* for (int h = 0; h < i; h++)
    {
        printf("%c", packet_ts[h]);
    }
    printf("\n"); */
    return i;
}

int handle_rrq_packet(char packet_to_recv[], unsigned short * bloackno, FILE * file, size_t n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        fputc(packet_to_recv[PACKET_HEAD + i], file);
    }
    return i;
}

int check_error(int f)
{
	return (f < 0) ? 1 : 0;
}

int is_block_num_ack(char packet[], unsigned short block_num)
{
	unsigned short block_num_echo = (packet[2] << 8) | (packet[3] & 0xFF);
    okay("local: %hu|server: %hu", block_num, block_num_echo);

	if (block_num_echo == block_num)
	{
		return 1;
	}
	return 0;
}

int prepare_data_packet(unsigned short blockno, FILE *file, char packet[])
{
	// trick to get the two chars by manipulating bits to convert 2B short into two characters
	char one = blockno >> 8;
	char two = blockno;
	int read_elems = -1;

	packet[0] = 0;
	packet[1] = OP_DATA; // OP code: 2B
	packet[2] = one;
	packet[3] = two; // Blockno: 2B

	read_elems = fread(packet + PACKET_HEAD, 1, PACKET_DATA_SIZE, file);
	okay("sending %i:%p:%s", read_elems, file, &packet[PACKET_HEAD]);
	return read_elems;
}

FILE * open_file(char filename[], char mode[])
{
    FILE * file = NULL;
    if (strchr(filename, '/') != NULL)
    {
        error("given file name contains '/'");
    }
    else
    {
        file = fopen(filename, mode);
    }
    return file;
}