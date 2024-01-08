#include <netinet/in.h>
#include <netinet/tcp.h>

#define MAX_EXEP 1024

#define ETH_HEADER_SIZE 14

typedef enum packet_type_e
{
    FIN_P_TYPE = TH_FIN,
    SYN_P_TYPE = TH_SYN,
    RST_P_TYPE = TH_RST,
    PSH_P_TYPE = TH_PUSH,
    ACK_P_TYPE = TH_ACK,
    URG_P_TYPE = TH_URG,
    ERR_P_TYPE = -1
    // ECE_P_TYPE = TH_ECE,
    // CWR_P_TYPE = TH_CWR,
} packet_type_e;

typedef enum packet_exep_e
{
    NORMAL_EXEP = 21,
    DUP_ACK_EXEP,
    ZERO_WINDOW,
    TIMEOUT_EXEP,
    RETRANS_EXEP
} packet_exep_e;

typedef struct packet_exep_node_s{
    struct in_addr src_ip, dest_ip;
    packet_exep_e exep;
    uint32_t packet_location;
}packet_exep_node_s;

packet_exep_e get_packet_exep(u_char * tcp_packet);
packet_type_e analyze_packet(u_char * tcp_packet);