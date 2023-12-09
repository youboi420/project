#include "../includes/headers.h"

int main(int argc, char *argv[])
{
	/* 	 Initialization of recieved packet from server
	 Is 4B + 512B = 516B (header and data sections)
	 Block number to keep track of data packets consecutively
	 Program times out when value reaches TIMEOUT_LIMIT tries on same packet */
	char packet[PACKET_SIZE] = "\0", prev_packet[PACKET_SIZE] = "\0", filename[STR_FILE_LIMIT] = "\0", mode[STR_FILE_LIMIT] = "\0";
	unsigned short blockno = 1, timeout_cnter = 0, potential_err, op_code = OP_END;
	struct sockaddr_in server, client;
	int packet_size = PACKET_DATA_SIZE, server_sock, flag = 0, connection;
	socklen_t len;
	ssize_t n;
	FILE *file = NULL;

	if (argc == 3)
	{
		okay("Server listening on port: %s\n", argv[1]);
	
		server_sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (check_error(server_sock)) exit_prog("bind failed");
		memset(&server, 0, sizeof(server));
		server.sin_family = AF_INET;

		// Converting arguments from host byte order to network byte order
		// Then binding address to socket using arguments
		server.sin_addr.s_addr = htonl(INADDR_ANY);
		server.sin_port = htons(atoi(argv[1]));
		flag = bind(server_sock, (struct sockaddr *)&server, (socklen_t)sizeof(server));
		if (check_error(flag)) exit_prog("bind failed");
		okay("awaiting request's");
		// while(1 == 1)
		// {
			// connection = rec(server_sock, 1);
			// okay("got connection", timeout_cnter);
			len = (socklen_t)sizeof(client);
			n = recvfrom(server_sock, packet, sizeof(packet) - 1, 0, (struct sockaddr *)&client, &len);
			while (packet_size == PACKET_DATA_SIZE)
			{
				okay("got %zi", n);
				packet[n] = '\0';
				potential_err = 1;
				file = handle_first_packet(packet, &blockno, &potential_err, file, filename, mode, argv[2], inet_ntoa(client.sin_addr));
				if (op_code == OP_END) op_code = packet[1];
				if (file == NULL)
				{
					// Form an error message appropriate to error type
					char err_msg[PACKET_DATA_SIZE] = "\0";
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
					okay("op code is: %i", op_code);
					if (op_code == OP_WRQ)
					{
						okay("not supperted yet - %p", file);
						file = NULL;
						// while(1)
						// {
						// 	/* get the file and write it to server folder argv[2] */
						// }
						break; /* exit the inner while loop */
						packet_size = 0;
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
					if (timeout_cnter >= 4)
					{
						prepare_error_packet(0, "ERROR: Transfer timed out", packet);
						if (check_error(sendto(server_sock, packet, (size_t)packet_size + 4, 0, (struct sockaddr *)&client, len))) exit_prog("send failed");
						exit_prog("Transfer timed out");
					}
				}
				if (check_error(sendto(server_sock, packet, (size_t)packet_size + PACKET_HEAD, 0, (struct sockaddr *)&client, len)) && op_code == OP_RRQ) exit_prog("send failed");
			}
			
			if (op_code != OP_WRQ) okay("SUCCESS: File transferred\n");
			else okay("SUCCESS: File transferred from client to server\n");
			if (file)
			{
				fclose(file);
			}
			op_code = OP_END;
			okay("while loop ended %p", file);
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

int write_data_packet(FILE *file, char packet[], int packet_size)
{
    size_t n = fwrite(packet + PACKET_HEAD, 1, packet_size - PACKET_HEAD, file);
    okay("Written %zu bytes. \tReceived data for write request: [%s]\n", n , packet + PACKET_HEAD);
	return n;
}

FILE *handle_first_packet(char packet[], unsigned short *block_num, unsigned short *potential_err, FILE *file, char filename[], char mode[], char folder[], char IP[])
{
	unsigned short OP_code = packet[1];
	okay("%hu\tfirst packet is: %s", OP_code ,&packet[1]);
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

	int file_idx = 2, i = 0;
	FILE *file = NULL;

	for (; packet[file_idx] != '\0'; file_idx++)
	{
		filename[file_idx - 2] = packet[file_idx];
	}
	filename[file_idx] = '\0';

	file_idx++;
	for (; packet[file_idx] != '\0'; file_idx++)
	{
		mode[i] = packet[file_idx];
		i++;
	}
	mode[i] = '\0';

	if (is_filename_valid(filename))
	{
		file = open_file(filename, folder, mode);
	}

	if (file)
	{
		okay("Starting transmission of packets\n");
	}
	return file;
}

FILE *open_file(char filename[], char folder[], char mode[])
{
	char full_path[100] = "\0";
	FILE *file;

	build_file_path(filename, folder, full_path);
	okay("Path requested: \"%s\"\n", full_path);
	file = fopen(full_path, "r");
	return (file != NULL) ? file : NULL;
}

FILE* handle_write_rqst(char filename[], char mode[], char packet[], char folder[])
{
	okay("file: %s|%s\tmode: %s", filename, folder, mode);
	return NULL;
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
	strcat(full_path, folder);
	strcat(full_path, "/");
	strcat(full_path, filename);
}

int prepare_data_packet(unsigned short blockno, FILE *file, char packet[])
{
	// trick to get the two chars by manipulating bits to convert 2B short into two characters
	char one = blockno >> 8;
	char two = blockno;
	int read_elems;

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
	{
		if (strstr(filename, "/") == NULL)
		{
			return 1;
		}
	}
	return 0;
}

int check_error(int f)
{
	return (f < 0) ? 1 : 0;
}

void exit_prog(char err_msg[])
{
	error("{%s}\n", err_msg);
	exit(EXIT_FAILURE);
}