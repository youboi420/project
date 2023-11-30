#include "../includes/headers.h"

// pretty sure it's to use the pcap lib
// #include <ctype.h>

int main(int argc, char* argv[])
{
    char receivedPacket[PACKET_SIZE] = "\0", requestedFilename[50] = "\0", requestedMode[50] = "\0", previousPacket[PACKET_SIZE] = "\0";
    int serverSocket, packetSize = PACKET_SIZE-4, net_flag; /*for flags*/ 
    unsigned short blockNumber = 1;
    unsigned short timeoutCounter = 0;
    unsigned short potentialError = 1;
    FILE* requestedFile = NULL;
    struct sockaddr_in server, client;
    
    if (argc == 3){
        serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
        // config the server struct
        memset(&server, 0, sizeof(server));
        
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = htonl(INADDR_ANY);
        server.sin_port = htons(atoi(argv[1]));
        
        net_flag = bind(serverSocket, (struct sockaddr*)&server, (socklen_t)sizeof(server));
        if(check_error(net_flag)) exit_prog();

        
    } else {
        error("incorrect number of parameters");
    }
}

FILE* handle_read_rqst(char filename[], char mode[], char packet[], char folder[])
{
    int file_idx = 2;
    FILE* file = NULL;
    int i = 0;

    for (; packet[file_idx] != '\0'; file_idx++) {
        filename[file_idx - 2] = packet[file_idx];
    }
    filename[file_idx] = '\0';
    file_idx++;
    for (; packet[file_idx] != '\0'; file_idx++) {
        mode[i] = packet[file_idx];
        i++;
    }
    mode[i] = '\0';
    if (is_filename_valid(filename)) {
        file = open_requested_file(filename, folder);
    }
    if (file) {
        okay("starting transmission of packets\n");
    }
    return file;
}

FILE* open_requested_file(char filename[], char folder[])
{
    // limit the path to PATH_LIMIT and initilize it to \0
    char full_path[PATH_LIMIT] = "\0";
    FILE* file;
    
    // build the full path 
    build_file_path(filename, folder, full_path);
    okay("path requested: \"%s\"\n", full_path);
    file = fopen(full_path, "r");
    
    if (file) {
        return file;
    } else {
        return NULL;
    }
}

FILE* handle_packet(char packet[], unsigned short* block_number, unsigned short* potential_err, FILE* file, char filename[], char mode[], char folder[], char clientIP[])
{
    unsigned short op_code = packet[1];
    switch (op_code) {
        case OP_RRQ:
            okay("Read request received from client: %s\n", clientIP);
            file = handle_read_rqst(filename, mode, packet, folder);
            break;
        case OP_WRQ:
            okay("Write request received from client: %s\n", clientIP);
            file = NULL;
            (*potential_err) = 3;
            break;
        case OP_ACK:
            if (is_block_num_ack(packet, block_number[0])) {
                (*block_number)++;
            } else {
                (*potential_err) = 2;
            }
            break;
        case OP_ERROR:
            error("error code %d: %s\n", packet[3], (packet + 4));
        default:
            (*potential_err) = 0;
            file = NULL;
            break;
    }
    return file;
}

int check_error(int f)
{
    return (f < 0) ? 1 : 0;
}

int is_filename_valid(char filename[])
{
    if (filename && (strstr(filename, "/") == NULL)) return 1;
    return 0;
}

int is_block_num_ack(char packet[], unsigned short block_number)
{
    // Extract the block number echo from the TFTP packet using shift<<8 | (mask)
    unsigned short block_number_echo = (packet[2] << 8) | (packet[3] & 0xFF);
    // Check if the extracted block number echo matches the expected block number
    return (block_number_echo == block_number) ? 1 : 0;
}

void build_file_path(char filename[], char folder[], char full_path[])
{
    strcat(full_path, "../");
    strcat(full_path, folder);
    strcat(full_path, "/");
    strcat(full_path, filename);
}

void prepare_error_packet(unsigned short err_code, char err_msg[], char packet[]) 
{
    unsigned int i = 4;
    packet[0] = 0;
    packet[1] = OP_ERROR;
    packet[2] = 0;
    packet[3] = err_code;
    // until the end of the err msg
    for (; err_msg[i - 4] != '\0'; i++) {
        packet[i] = err_msg[i - 4];
    }
    packet[i] = '\0';
}

int prepare_data_packet(unsigned short block_num, FILE* file, char packet[])
{
    char first_byte = block_num >> 8;
    char second_byte = block_num;
    int read_elements;

    packet[0] = 0;
    packet[1] = OP_DATA;
    packet[2] = first_byte;
    packet[3] = second_byte;
    read_elements = fread(packet + 4, 1, 512, file);

    return read_elements;
}

void exit_prog(){
    error("program failed");
    exit(EXIT_FAILURE);
}