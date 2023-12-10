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

/**
 * @brief he function takes the given file name and directory, tries to open the file,
 * and returns a file pointer. If the file exists in the specified directory,
 * it returns the pointer to it; otherwise, it returns NULL.
 * 
 * @param filename the filename to open
 * @param folder the folder containing the file.
 * @return FILE* 
 */
FILE* open_file(char filename[], char folder[], char mode[]);

/**
 * @brief 
 * 
 * @param filename the file name to write to
 * @param mode the mode
 * @param packet the packet containing the data to write
 * @param folder the folder to write said file to
 * @return FILE* the written file if successful, otherwise null.
 */
FILE* handle_read_rqst(char filename[], char mode[], char packet[], char folder[]);

FILE* handle_write_rqst(char filename[], char mode[], char packet[], char folder[]);
/**
 * @brief the function process the recieved TFTP PACKET, updates tge block number handles
 * RRQ and ACK and it returns the updated file pointer
 * 
 * @param packet the received packet
 * @param block_number pointer to block num
 * @param potential_err pointer to potential err code
 * @param file the file pointer
 * @param filename the file name
 * @param mode the transfering mode
 * @param folder the folder containing the file
 * @param clientIP the ip of the client
 * @return FILE* the updated file pointer
 */
FILE* handle_first_packet(char packet[], unsigned short* block_number, unsigned short* potential_err, FILE* file, char filename[], char mode[], char folder[], char clientIP[]);

/**
 * @brief creates the error packet with error code and the custom message  
 * 
 * @param err_code says what error 
 * @param err_msg the custom error msg
 * @param packet the packet to prepare
 */
void prepare_error_packet(unsigned short err_code, char err_msg[], char packet[]);

/**
 * @brief the function creates the full path with the given folder
 * 
 * @param filename filename
 * @param folder destination folder
 * @param fullPath the char[] to write to
 */
void build_file_path(char filename[], char folder[], char fullPath[]);

void extract_names(char filename[], char mode[], char packet[]);

void prepare_ack_packet(unsigned short blockno, char packet[]);

void wrq_func(socklen_t len, int n, FILE * file, char packet[], int server_sock, struct sockaddr_in client);

/**
 * @brief like prepare error packet. it prepares the packet to send with the data (file content)
 * and the block number 
 * 
 * @param blockNumber 
 * @param file the file pointer
 * @param packet the packet to prepare
 * @return int returns how much data is read from file pointer
 */
int prepare_data_packet(unsigned short blockNumber, FILE* file, char packet[]);

/**
 * @brief checks if the reveiced packet is ack's the specified blocknum
 * 
 * @param packet char[]
 * @param blockNumber unsigned short
 * @return int returns 1 if the block is acked otherwise 0.
 */
int is_block_num_ack(char packet[], unsigned short blockNumber);


/**
 * @brief checks if the file contains a '/'
 * 
 * @param filename char[] to check
 * @return int returns 1 if the file doesnt contain '/' otherwise 0.
 */
int is_filename_valid(char filename[]);

/**
 * void to a function that doesnt take any param's
 * switch case
 * custom message in exit func
 * 
 * @brief exit the program if given flag is less then 0
 * 
 * @param f the flag to determin if exit or not
 * @return int 
 */
int check_error(int f);
/**
 * @brief exit the program with custom message
 * 
 * @param err_msg the custom error message
 */
void exit_prog(char err_msg[]);