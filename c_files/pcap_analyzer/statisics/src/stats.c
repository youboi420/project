#include "../includes/headers.h"
#include "../includes/hash_table.h"
#include "../includes/conversations.h"
/* GLOBALS */
char hosts_g[MAX_HOSTS][MAX_HOST_LEN];
char ports_g[MAX_PORTS][MAX_PORT_LEN];
ENTRY tcp_conversation_table_g[MAX_TCP_CONVERSATIONS];
int num_hosts_g = 0, num_ports_g, p_counter_g = 0;


/* Finds the payload of a TCP/IP packet */
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_header;
    struct ip * ip_hdr_s;
    struct tcphdr * tcp_hdr_s;
    struct udphdr *udp_hdr_s;
    const int ethernet_header_length = 14, udp_header_length = 8;;
    const u_char *ip_header, *tcp_header, *udp_header, *payload, *temp_pointer;
    char *source_ip, *dest_ip, *source_port_str,*dest_port_str;
    u_char protocol;
    int ip_header_length, tcp_header_length, payload_length, total_headers_size, byte_count = 0;
    uint16_t source_port, dest_port;
    
    p_counter_g++;
    printf("\n");
    okay("--------------packet [%i/%i]----------------", p_counter_g, MAX_PACKETS);
    eth_header = (struct ether_header *)packet; /* make sure we have an IP packet */
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) /* if not continue to next packet */
    {
        error("Not an IP packet. Skipping...");
        return;
    }

    okay("Total packet available: %d bytes", header->caplen);
    okay("Expected packet size: %d bytes", header->len);
    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    ip_hdr_s = (struct ip *)ip_header;
    okay("IP header length (IHL) in bytes: %d", ip_header_length);

    source_ip = malloc(MAX_HOST_LEN);
    dest_ip = malloc(MAX_HOST_LEN);

    strncpy(source_ip, inet_ntoa(ip_hdr_s->ip_src), MAX_HOST_LEN);
    strncpy(dest_ip, inet_ntoa(ip_hdr_s->ip_dst), MAX_HOST_LEN);

    okay("Source ip: [%s]", source_ip);
    okay("Destantion ip: [%s]", dest_ip);

    if (add_host(source_ip, hosts_g)) num_hosts_g++;
    free(source_ip);
    
    if (add_host(dest_ip, hosts_g)) num_hosts_g++;
    free(dest_ip);
    /* Now that we know where the IP header is, we can
       inspect the IP header for a protocol number to
       make sure it is TCP before going any further.
       Protocol is always the 10th byte of the IP header */
    protocol = *(ip_header + 9);
    // if (protocol == IPPROTO_TCP)
    // {
    //     error("Not a TCP packet. Skipping...");
    //     return;
    // }
    switch (protocol)
    {
    case IPPROTO_TCP:
        tcp_header = packet + ethernet_header_length + ip_header_length;
        tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;/*   The TCP header length stored in those 4 bits represents
                                                                    how many 32-bit words there are in the header, just like the IP header length.
                                                                    We multiply by four again to get a byte count. */
        tcp_header_length = tcp_header_length * 4;
        okay("TCP header length in bytes: %d", tcp_header_length);
        total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
        okay("Size of all headers combined: %d bytes", total_headers_size);
        payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
        okay("Payload size: %d bytes", payload_length);
        payload = packet + total_headers_size;
        if (0)
        {    /* okay("Memory address where payload begins: %p", payload); // no need */
            if (payload_length > 0)
            {
                temp_pointer = payload;
                byte_count = 0;
                while (byte_count++ < payload_length)
                {
                    printf("%c", *temp_pointer);
                    temp_pointer++;
                }
                printf("\n");
            }
        }
        tcp_hdr_s = (struct tcphdr *)tcp_header;
        source_port = ntohs(tcp_hdr_s->th_sport);
        dest_port = ntohs(tcp_hdr_s->th_dport);
        okay("Source port: %d", source_port);
        okay("Destination port: %d", dest_port);
        source_port_str = malloc(MAX_HOST_LEN);
        dest_port_str = malloc(MAX_HOST_LEN);
        snprintf(source_port_str, MAX_PORT_LEN, "%u", source_port);
        snprintf(dest_port_str, MAX_PORT_LEN, "%u", dest_port);
        if (add_port(source_port_str, ports_g)) num_ports_g++;
        if (add_port(dest_port_str, ports_g)) num_ports_g++;
        free(source_port_str);
        free(dest_port_str);
        break;
    case IPPROTO_UDP:
        udp_header = packet + ethernet_header_length + ip_header_length;
        okay("UDP header length in bytes: %d", udp_header_length);
        total_headers_size = ethernet_header_length + ip_header_length + udp_header_length;
        okay("Size of all headers combined: %d bytes", total_headers_size);
        payload_length = header->caplen - total_headers_size;
        okay("Payload length: %d bytes", payload_length);
        payload = packet + total_headers_size;
        if (payload_length > 0) {
            temp_pointer = payload;
            byte_count = 0;
            while (byte_count++ < payload_length) {
                printf("%c", *temp_pointer);
                temp_pointer++;
            }
            printf("\n");
            
        }
        udp_hdr_s = (struct udphdr *)udp_header;
        source_port = ntohs(udp_hdr_s->uh_sport);
        dest_port = ntohs(udp_hdr_s->uh_dport);
        okay("Source port: %d", source_port);
        okay("Destination port: %d", dest_port);
        source_port_str = malloc(MAX_HOST_LEN);
        dest_port_str = malloc(MAX_HOST_LEN);
        snprintf(source_port_str, MAX_PORT_LEN, "%u", source_port);
        snprintf(dest_port_str, MAX_PORT_LEN, "%u", dest_port);
        if (add_port(source_port_str, ports_g)) num_ports_g++;
        if (add_port(dest_port_str, ports_g)) num_ports_g++;
        free(source_port_str);
        free(dest_port_str);
        break;

    default:
        return;
        break;
        
    }
}

int main(int argc, char **argv)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int total_packet_count = MAX_PACKETS;
    u_char *my_arguments = NULL;
    const char filename[] = "myfile200.pcap";
    
    init_hosts_table(hosts_g);
    init_ports_table(ports_g);
    handle = pcap_open_offline(filename, error_buffer);
    if (handle == NULL)
    {
        error("error opening %s:%s", filename, error_buffer);
        exit(EXIT_FAILURE);
    }
    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);
    print_hosts_table(hosts_g, num_hosts_g); /* prints all the captured hosts */
    print_ports_table(ports_g, num_ports_g); /* prints all the captured ports */
    return 0;
}