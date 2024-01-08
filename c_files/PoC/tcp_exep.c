#include "./includes/tcp_exep.h"

packet_exep_e get_packet_exep(u_char * tcp_packet)
{
    int ret_val = NORMAL_EXEP;
    return ret_val;
}
packet_type_e analyze_packet(u_char * tcp_packet)
{
    int ret_val = ERR_P_TYPE;
    // struct tcphdr *tcp_header;
    // struct ip *ip_header;
    // ip_header = (struct ip *)(tcp_packet + ETH_HEADER_SIZE);

    return ret_val;
}