#include "../includes/headers.h"

int main(int argc, char *argv[])
{
	/* 	
		Initialization of recieved packet from server
		Is 4B + 512B = 516B (header and data sections)
		Block number to keep track of data packets consecutively
		Program times out when value reaches TIMEOUT_LIMIT tries on same packet
	*/
	char packet[PACKET_SIZE + 1] = "\0", prev_packet[PACKET_SIZE] = "\0", filename[STR_FILE_LIMIT] = "\0", mode[STR_FILE_LIMIT] = "\0", err_msg[PACKET_DATA_SIZE] = "\0";
	unsigned short blockno = 1, timeout_cnter = 0, potential_err, op_code = OP_END;
	struct sockaddr_in server, client;
	int packet_size = PACKET_DATA_SIZE, server_sock, flag = 0, connection, write_count = -1;
	socklen_t len;
	ssize_t n;
	FILE *file = NULL;

	if (argc == 3)
	{
		okay("Server listening on port: %s\n", argv[1]);
	
		server_sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (check_error(server_sock)) exit_prog("sock asign failed");
		memset(&server, 0, sizeof(server));
		server.sin_family = AF_INET;
		server.sin_addr.s_addr = htonl(INADDR_ANY);
		server.sin_port = htons(atoi(argv[1]));
		flag = bind(server_sock, (struct sockaddr *)&server, (socklen_t)sizeof(server));
		if (check_error(flag)) exit_prog("bind failed");
		okay("awaiting request's");
		// while(1 == 1)
		// {
			// connection = rec(server_sock, 1);
			// okay("got connection", timeout_cnter);
			while (packet_size == PACKET_DATA_SIZE)
			{
				/* possible fix to contain inside an if (n == 0) ??? */
				len = (socklen_t)sizeof(client);
				n = recvfrom(server_sock, packet, sizeof(packet) - 1, 0, (struct sockaddr *)&client, &len);
				packet[n] = '\0';
				potential_err = 1;
				file = handle_first_packet(packet, &blockno, &potential_err, file, filename, mode, argv[2], inet_ntoa(client.sin_addr));
				if (op_code == OP_END) op_code = packet[1];
				if (file == NULL)
				{
					if (potential_err == 1)
						strcat(err_msg, "ERROR: File name and/or directory could not be resolved");
					else
						strcat(err_msg, "ERROR: Unable to resolve packet");
					prepare_error_packet(potential_err, err_msg, packet);
					if (check_error(sendto(server_sock, packet, (size_t)packet_size + 4, 0, (struct sockaddr *)&client, len))) exit_prog("send failed");
					exit_prog(err_msg); /* after fail return to while loop */
				}
				if (potential_err != 2)
				{
					if (op_code == OP_WRQ)
					{
						okay("huh?");
						prepare_ack_packet(0, packet);
						if (check_error(sendto(server_sock, packet, PACKET_HEAD, 0, (struct sockaddr *)&client, sizeof(client)))) {
							exit_prog("sendto failed");
						}
						while (1)
						{
							len = (socklen_t)sizeof(client);
							n = recvfrom(server_sock, packet, sizeof(packet) - 1, 0, (struct sockaddr *)&client, &len);
							if (check_error(n))
							{
								error("connection timed out?");
								/* exit_prog(""); */
								break;
							}
							packet[n] = '\0';
							if ((strcmp(mode, "wb"))) fwrite(packet + PACKET_HEAD, 1, n - PACKET_HEAD, file);
							else write_count = write_data_packet(file, packet, n-PACKET_HEAD);
							if (write_count != n - PACKET_HEAD) exit_prog("Error writing to file");
							prepare_ack_packet(blockno, packet);
							if (check_error(sendto(server_sock, packet, (size_t)packet_size + PACKET_HEAD, 0, (struct sockaddr *)&client, len))) exit_prog("send failed");
							
							/* end writing while loop if EOF */
							if (n < PACKET_DATA_SIZE + PACKET_HEAD)
							{
								okay("File transfer complete");
								fclose(file);
								file = NULL;
								break;
							}
							blockno++;
						}
						packet_size = 0; /* to quit inner while loop */
						break; /* exit the inner while loop */
					}
					else
					{
						packet_size = prepare_data_packet(blockno, file, packet);
						*prev_packet = *packet;
						timeout_cnter = 0;
					}
				}
				else
				{
					*packet = *prev_packet;
					timeout_cnter++;
					if (timeout_cnter >= TIMEOUT_LIMIT)
					{
						prepare_error_packet(0, "ERROR: Transfer timed out", packet);
						if (check_error(sendto(server_sock, packet, (size_t)packet_size + 4, 0, (struct sockaddr *)&client, len))) exit_prog("send failed");
						exit_prog("Transfer timed out");
					}
				}
				okay("packet: [%s]", packet);
				if (check_error(sendto(server_sock, packet, (size_t)packet_size + PACKET_HEAD, 0, (struct sockaddr *)&client, len)) && op_code == OP_RRQ) exit_prog("send failed");
			}
			
			if (op_code != OP_WRQ) okay("SUCCESS: File transferred\n");
			else okay("SUCCESS: File transferred from client to server\n");
			if (file)
			{
				fclose(file);
				okay("file was closed");
			}
			op_code = OP_END;
			// packet_size = PACKET_DATA_SIZE;
			// file = NULL;
		// } /* end of outer while */
	}
	else
	{
		exit_prog("ERROR: Incorrect number of parameters");
	}
	return EXIT_SUCCESS;
}

int write_data_packet(FILE *file, char packet[], size_t n)
{
    size_t i;
	for (i = 0; i < n; i++)
	{
		fputc(packet[PACKET_HEAD + i], file);
		/* code */
	}
	
    okay("Written %zu bytes. \tReceived data for write request: [%s]\n", n , packet + PACKET_HEAD);
	return i;
}

FILE *handle_first_packet(char packet[], unsigned short *block_num, unsigned short *potential_err, FILE *file, char filename[], char mode[], char folder[], char IP[])
{
	unsigned short OP_code = packet[1];
	okay("OP: %hu\tfirst packet is: %s", OP_code ,&packet[1]);
	switch (OP_code)
	{
		case OP_RRQ:
			okay("Read request received from client: %s\n", IP);
			file = handle_read_rqst(filename, mode, packet, folder);
			break;
		case OP_WRQ:
			okay("Write request received from client: %s\n", IP);
			file = handle_write_rqst(filename, mode, packet, folder);
			// file = NULL;
			// (*potential_err) = 3;
			break;
		case OP_ACK:
			if (is_block_num_ack(packet, block_num[0]))
			{
				(*block_num)++;
			}
			else
			{
				(*potential_err) = 2;
			}
			break;
		case OP_ERROR:
			error("Error code %d: %s\n", packet[3], (packet + PACKET_HEAD));
		default:
			(*potential_err) = 0;
			file = NULL;
			break;
	}
	return file;
}

FILE *handle_read_rqst(char filename[], char mode[], char packet[], char folder[])
{
	FILE *file = NULL; 
	extract_names(filename, mode, packet);
	file = open_file(filename, folder, mode);
	if (file)
	{
		okay("Starting transmission {READING TO CLIENT}of packets\n");
	}
	return file;
}

FILE *open_file(char filename[], char folder[], char mode[])
{
	char full_path[100] = "\0";
	FILE *file = NULL;

	build_file_path(filename, folder, full_path);
	if (is_filename_valid(filename))
		file = fopen(full_path, mode); /* mode instead of 'r' */

	return file;
}

FILE* handle_write_rqst(char filename[], char mode[], char packet[], char folder[])
{
	FILE * file = NULL;
	extract_names(filename, mode, packet);
	file = open_file(filename, folder, mode);
	if (file)
		okay("Starting transmission {WRITING FROM CLIENT} of packets\n");
	return file;
}
void prepare_error_packet(unsigned short err_code, char err_msg[], char packet[])
{
	unsigned int i = PACKET_HEAD;

	packet[0] = 0;
	packet[1] = OP_ERROR; // OP code 2B
	packet[2] = 0;
	packet[3] = err_code; // Error code 2B

	for (; err_msg[i - PACKET_HEAD] != '\0'; i++)
	{
		packet[i] = err_msg[i - PACKET_HEAD];
	}
	packet[i] = '\0';
}

void build_file_path(char filename[], char folder[], char full_path[])
{
	/*strcat(full_path, "../"); */
	strcat(full_path, folder);
	strcat(full_path, "/");
	strcat(full_path, filename);
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

int is_block_num_ack(char packet[], unsigned short block_num)
{
	unsigned short block_num_echo = (packet[2] << 8) | (packet[3] & 0xFF);
	if (block_num_echo == block_num)
	{
		return 1;
	}
	return 0;
}

int is_filename_valid(char filename[])
{
	if (filename)
		if (strstr(filename, "/") == NULL)
			return 1;
	return 0;
}

int check_error(int f)
{
	return (f < 0) ? 1 : 0;
}

void extract_names(char filename[], char mode[], char packet[])
{
	int file_idx = 2, i = 0;
	unsigned short op_c = packet[1];

	for (; packet[file_idx] != '\0'; file_idx++)
		filename[file_idx - 2] = packet[file_idx];

	filename[file_idx] = '\0';
	/* okay("extracted: %s", filename); */
	file_idx++;
	for (; packet[file_idx] != '\0'; file_idx++, i++)
		mode[i] = packet[file_idx];
	/* if (strcmp(mode, "netascii") == 0)
		okay("text mode: %s", mode);
	else if (strcmp(mode, "binary") == 0)
		okay("bin mode: %s", mode); */
	mode[i] = '\0';

	if ((strcmp(mode, "netascii") == 0) && op_c == OP_RRQ)
		strcpy(mode, "r");
	else if ((strcmp(mode, "octet") == 0) && op_c == OP_RRQ)
		strcpy(mode, "rb");
	else if ((strcmp(mode, "netascii") == 0) && op_c == OP_WRQ)
		strcpy(mode, "wb");
	else if ((strcmp(mode, "octet") == 0) && op_c == OP_WRQ)
		strcpy(mode, "wb");
	okay("file: [%s]\tmode is: [%s]", filename,mode);
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

void exit_prog(char err_msg[])
{
	error("{%s}\n", err_msg);
	exit(EXIT_FAILURE);
}