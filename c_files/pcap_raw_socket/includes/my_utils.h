#pragma once
#include "headers.h"

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] INFO: " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

// /**
//  * @brief Creates a raw socket for the sniffer 
//  * 
//  * @return int - the raw sock_fd
//  */
// int create_raw_socket(void);

int my_kbhit(void);

void setup_device_file(pcap_dumper_t **pcap_dumper, pcap_t ** handle, char filename[]);
void set_non_blocking_mode(void);
void stopable_capture(pcap_t *handle, int capture_limit, pcap_handler packet_handler, void *user_data);
void main_packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void exit_prog(char err_msg[]);