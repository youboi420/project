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

int check_error(int f);
void check_args(char const *argv[]);
void exit_prog(char err_msg[]);

/**
 * @brief print's the usage of this program
 * 
 */
void usage(void);