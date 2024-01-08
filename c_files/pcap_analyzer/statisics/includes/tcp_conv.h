#include "hash_table.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <search.h>

// #define MAX_TCP_CONVERSATIONS 3

typedef struct tcp_conversation {
    char src_ip[MAX_HOST_LEN];
    char dst_ip[MAX_HOST_LEN];
    uint16_t src_port, dst_port;
    uint32_t packet_count, retrans_time;
    uint64_t total_bytes_rcvd, total_bytes_sent;
    double avg_rtt; /* round trip time */
    struct timeval start_time, end_time;
    struct tcp_packet *packets;  // Linked list of TCP packets
    // ... other fields for sequence numbers, timestamps, flags, etc.
} tcp_conversation_t;

tcp_conversation_t *find_or_create_conversation(struct tcphdr *tcp_header, struct ip * ip_header);

// ... (other functions for storing packet details, analysis, etc.)

// void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
//     // ... (existing code)

//     if (protocol == IPPROTO_TCP) {
//         tcp_header = packet + ethernet_header_length + ip_header_length;
//         // ... (existing TCP header parsing)

//         // Create or retrieve conversation
//         tcp_conversation_t *conversation = find_or_create_conversation(tcp_header);

//         // Store packet details in conversation
//         // ... (implementation for storing packet details)
//     }
// }