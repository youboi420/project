#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#define PATH_LIMIT 256
#define PACKET_SIZE 516
enum OP_CODES { OP_RRQ = 1, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR };
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] INFO: " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
/*
    functions sig
*/

FILE* open_requested_file(char filename[], char folder[]);
FILE* handle_read_rqst(char filename[], char mode[], char packet[], char folder[]);
FILE* handle_packet(char packet[], unsigned short* block_number, unsigned short* potential_err, FILE* file, char filename[], char mode[], char folder[], char clientIP[]);

void prepare_error_packet(unsigned short err_code, char err_msg[], char packet[]);
void exit_prog();
void build_file_path(char filename[], char folder[], char fullPath[]);

int prepare_data_packet(unsigned short blockNumber, FILE* file, char packet[]);
int is_block_num_ack(char packet[], unsigned short blockNumber);
int is_filename_valid(char filename[]);
int check_error(int f);