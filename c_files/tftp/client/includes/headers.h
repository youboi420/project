#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#define PATH_LIMIT 256
#define PACKET_SIZE 516
#define PACKET_HEAD 4
#define PACKET_ACK_SIZE 4
#define STR_FILE_LIMIT 50 
#define PACKET_DATA_SIZE 512
#define TIMEOUT_LIMIT 5
#define PORT_LEN 6
#define MAX_PORT 65535
#define MIN_PORT 1024
enum OP_CODES 
{
    OP_RRQ = 1,
    OP_WRQ,
    OP_DATA,
    OP_ACK,
    OP_ERROR,
    OP_END
};

enum ERR_CODES
{
    TIME_ERR = 0,
    FILE_ERR,
    PACKET_ERR,
    WRITE_ERR
};

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] INFO: " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

/* functions sigs */

void handle_args(const char *argv[], char ip[], char port[], char mode[], char filename[], char operation[]);
void exit_prog(char err_msg[]);
void get_local_mode(char mode[], int op);
void prepare_ack_packet(unsigned short blockno, char packet[]);

FILE * open_file(char filename[], char mode[]);

int check_error(int f);
int prep_packet(char filename[], char mode[], char packet_ts[], int op);
int is_block_num_ack(char packet[], unsigned short block_num);
int handle_rrq_packet(char packet_to_recv[], unsigned short * bloackno, FILE * file, size_t n);

/**
 * @brief print's the usage of this program
 * 
 */
void usage(void);