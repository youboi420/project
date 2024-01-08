#pragma once
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>

#define MAX_TCP_CONVERSATIONS 3

/*
int flag = -1;
p_list_s p;
strncpy(p.packet, packet, MAX_PACKET_LEN);
p.next = NULL;
flag = insert_to_p_list(root, p);
if (check_error(flag))
{
    error("insert packet to p_list failed");
    return;
}

*/

typedef struct p_list {
    u_char * packet;
    struct p_list *next;
}p_list;

typedef struct INFO_ETH {
    uint16_t id;
    uint8_t mac_a[ETH_ALEN], mac_b[ETH_ALEN]; 
    uint16_t packets_num, packets_A_to_B, packets_B_to_A;
    double rel_start, duration, bytes_A_to_B, bytes_B_to_A;
    struct p_list * p_list_root;
} info_eth_s;

typedef struct INFO_IPv4 {
    uint16_t id;
    char addr_src[INET_ADDRSTRLEN], addr_dst[INET_ADDRSTRLEN];
    uint16_t packets_num, packets_A_to_B, packets_B_to_A;
    double rel_start, duration, bytes_A_to_B, bytes_B_to_A;
} info_ipv4_s;

typedef struct INFO_PROTOCOL {
    info_ipv4_s ip_info;
    uint16_t port_src, port_dst;
    uint8_t prot_type; /* IPPROTO_TCP or IPPROTO_UDP */
} info_protocol_s;
