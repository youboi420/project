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

/**
 * @brief copies the given args to the char[] accordingly argv[1] -> ip and so for
 * 
 * @param argv the cli args char *[] list of 'strings'
 * @param ip the char[] that will contain the argv[1]
 * @param port the char[] that will contain the argv[2]
 * @param mode the char[] that will contain the argv[3]
 * @param filename the char[] that will contain the argv[4]
 * @param operation the char[] that will contain the argv[5]
 */
void handle_args(const char *argv[], char ip[], char port[], char mode[], char filename[], char operation[]);

/**
 * @brief prints the error message and exits the program
 * 
 * @param err_msg the error message to be printed
 */
void exit_prog(char err_msg[]);

/**
 * @brief converts the given op to corresponding mode string
 * 
 * @param mode the char [] that will contain the mode string
 * @param op the unsigned short that represents the op code
 */
void get_local_mode(char mode[], int op);

/**
 * @brief prepares the ack packet to be sent to the server
 * 
 * @param blockno unsigned short that reprersents the block number of the packet
 * @param packet char [] that is the packet to prepare
 */
void prepare_ack_packet(unsigned short blockno, char packet[]);

/**
 * @brief opens the file and returns a FILE * with mode read or write netascii/octet
 * 
 * @param filename the name of the file to be readen/written
 * @param mode the local mode of the file to be readen/written
 * @return FILE* 
 */
FILE * open_file(char filename[], char mode[]);

/**
 * @brief if f is less then 0 it returns 1 indicating an error occured
 * 
 * @param f int. the flag
 * @return int determing if theres an error or not
 */
int check_error(int f);

/**
 * @brief prepares the packet to be sent to the server
 * 
 * @param filename tthe name of the file to be readen/written
 * @param mode the mode of the file to be readen/written (not local)
 * @param packet_ts char[] that will contain the packet to be sent
 * @param op unsigned short that represents the op code
 * @return int the size of the packet (no PACKET_HEAD)
 */
int prep_packet(char filename[], char mode[], char packet_ts[], int op);

/**
 * @brief checks if the packet is an ack packet depending on the packet block number echo
 * 
 * @param packet char[] that is the packet to be checked
 * @param block_num the block number of client's file
 * @return int 1 or 0 depending on the result
 */
int is_block_num_ack(char packet[], unsigned short block_num);

/**
 * @brief handles the read request, gets the data from the server and writes it to the file
 * 
 * @param packet_to_recv char[] that is the packet to be received from the server
 * @param bloackno 
 * @param file 
 * @param n 
 * @return int 
 */
int handle_rrq_packet(char packet_to_recv[], unsigned short * bloackno, FILE * file, size_t n);

/**
 * @brief prepares the data packet to be sent to the client by reading the file
 * 
 * @param blockNumber
 * @param file 
 * @param packet 
 * @return int which represents the number of bytes read from the file
 */
int prepare_data_packet(unsigned short blockNumber, FILE *file, char *packet);


/**
 * @brief print's the usage of this program
 * void doesnt take any arguments
 */
void usage(void);