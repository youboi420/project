#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

// pretty sure it's to use the pcap lib
// #include <ctype.h>

#define PATH_LIMIT 256

enum OpCode { OP_RRQ = 1, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR };
/*
    functions sig
*/
FILE* open_requested_file(char filename[], char folder[]);
FILE* handle_read_rqst(char filename[], char mode[], char packet[], char folder[]);
void prepare_error_packet(unsigned short errCode, char errMsg[], char packet[]);
int is_block_num_ack(char packet[], unsigned short blockNumber);
int is_filename_valid(char filename[]);
void exit_prog();
int check_error(int f);

int main(int argc, char* argv[])
{
    char receivedPacket[516] = "\0", requestedFilename[50] = "\0", requestedMode[50] = "\0", previousPacket[516] = "\0";
    int serverSocket, packetSize = 512, net_flag;
    unsigned short blockNumber = 1;
    unsigned short timeoutCounter = 0;
    unsigned short potentialError = 1;

    FILE* requestedFile = NULL;

    struct sockaddr_in server, client;
    serverSocket = socket(AF_INET, SOCK_DGRAM, 0);

    // config the server struct
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(atoi(argv[1]));
    net_flag = bind(serverSocket, (struct sockaddr*)&server, (socklen_t)sizeof(server));
    
    if(check_error(net_flag)) exit_prog();
}

void buildFilePath(char filename[], char folder[], char fullPath[])
{
    strcat(fullPath, "../");
    strcat(fullPath, folder);
    strcat(fullPath, "/");
    strcat(fullPath, filename);
}

FILE* open_requested_file(char filename[], char folder[])
{
    // limit the path to PATH_LIMIT and initilize it to \0
    char fullPath[PATH_LIMIT] = "\0";
    // build the full path 
    buildFilePath(filename, folder, fullPath);
    printf("Path requested: \"%s\"\n", fullPath);
    FILE* file = fopen(fullPath, "r");

    if (file) {
        return file;
    } else {
        return NULL;
    }
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

FILE* handlePacket(char packet[], unsigned short* blockNumber, unsigned short* potentialError, FILE* file, char filename[], char mode[], char folder[], char clientIP[])
{
    unsigned short opCode = packet[1];
    switch (opCode) {
        case OP_RRQ:
            printf("Read request received from client: %s\n", clientIP);
            file = handle_read_rqst(filename, mode, packet, folder);
            break;
        case OP_WRQ:
            printf("Write request received from client: %s\n", clientIP);
            file = NULL;
            (*potentialError) = 3;
            break;
        case OP_ACK:
            if (is_block_num_ack(packet, blockNumber[0])) {
                (*blockNumber)++;
            } else {
                (*potentialError) = 2;
            }
            break;
        case OP_ERROR:
            printf("Error code %d: %s\n", packet[3], (packet + 4));
        default:
            (*potentialError) = 0;
            file = NULL;
            break;
    }

    return file;
}

int is_block_num_ack(char packet[], unsigned short blockNumber)
{
    // Extract the block number echo from the TFTP packet
    unsigned short blockNumberEcho = (packet[2] << 8) | (packet[3] & 0xFF);
    // Check if the extracted block number echo matches the expected block number
    return (blockNumberEcho == blockNumber) ? 1 : 0;
}

FILE* handle_read_rqst(char filename[], char mode[], char packet[], char folder[])
{
    int fileIdx = 2;
    for (; packet[fileIdx] != '\0'; fileIdx++) {
        filename[fileIdx - 2] = packet[fileIdx];
    }
    filename[fileIdx] = '\0';

    fileIdx++;
    int i = 0;
    for (; packet[fileIdx] != '\0'; fileIdx++) {
        mode[i] = packet[fileIdx];
        i++;
    }
    mode[i] = '\0';

    FILE* file = NULL;
    if (is_filename_valid(filename)) {
        file = open_requested_file(filename, folder);
    }

    if (file) {
        printf("Starting transmission of packets\n");
    }

    return file;
}

void prepare_error_packet(unsigned short errCode, char errMsg[], char packet[]) 
{
    packet[0] = 0;
    packet[1] = OP_ERROR;
    packet[2] = 0;
    packet[3] = errCode;

    unsigned int i = 4;
    for (; errMsg[i - 4] != '\0'; i++) {
        packet[i] = errMsg[i - 4];
    }
    packet[i] = '\0';
}