#include <netinet/in.h>
#include <sys/types.h>

#include "tcp_exep.h"

typedef struct packet_node_s {
    u_char *packet_data;
    uint32_t p_id;
    size_t packet_length;
    size_t packet_type;
    size_t packet_exep;
    struct packet_node_s *next;
} packet_node_s;

typedef struct {
    uint16_t conv_id;
    struct in_addr src_ip;
    struct in_addr dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    int packets_from_a_to_b;
    int packets_from_b_to_a;
    int proto_type;
    int num_packets;
    packet_exep_node_s exep_packet_id[MAX_EXEP];
    packet_node_s * packet_list;
} conv_s;