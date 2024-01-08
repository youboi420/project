#include "./includes/conv.h"

#include <netinet/in.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <json-c/json.h>
#include <sys/types.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] INFO: " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...)printf("[-] " msg "\n", ##__VA_ARGS__)
#define MAX_CONVERSATIONS 1000
#define HASH_CONST 5381

/* GLOBALS */
conv_s conversations_arr[MAX_CONVERSATIONS];
unsigned int conv_hash_g;
uint16_t conv_id_tcp_g = 0, conv_id_udp_g = 0;

void init_list(packet_node_s ** root)
{
    *root = NULL;
}

void print_output_to_file(conv_s conversations[MAX_CONVERSATIONS], char * filename)
{
    FILE * tcp_file, *udp_file;
    char * out_filename = malloc(strlen(filename) + 4), src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    char p_type[4];
    int i;
    /* beggining of string or first ever / */
    strcpy(out_filename, "tcp_");
    strcat(out_filename, filename);
    out_filename[strlen(out_filename) - 4] = 't';
    out_filename[strlen(out_filename) - 3] = 'x';
    out_filename[strlen(out_filename) - 2] = 't';
    out_filename[strlen(out_filename) - 1] = '\0';
    tcp_file = fopen(out_filename, "w");

    strcpy(out_filename, "udp_");
    strcat(out_filename, filename);
    out_filename[strlen(out_filename) - 4] = 't';
    out_filename[strlen(out_filename) - 3] = 'x';
    out_filename[strlen(out_filename) - 2] = 't';
    out_filename[strlen(out_filename) - 1] = '\0';
    udp_file = fopen(out_filename, "w");

    if (!tcp_file || !udp_file)
    {
        error("error opening the file %s", out_filename);
        free(out_filename);
        return;
    }
    /* SOF TCP FILE */
    fprintf(tcp_file, "+---------------------------------------------------------------------------------------------------------------------------------------+\n");
    fprintf(tcp_file, "|\tID\t|\tAddress A\t|\tAddress B\t|\tPort A\t\t|\tPort B\t\t|\tPROTCOL\t\t|\n");

    /* SOF UDP FILE */
    fprintf(udp_file, "+---------------------------------------------------------------------------------------------------------------------------------------+\n");
    fprintf(udp_file, "|\tID\t|\tAddress A\t|\tAddress B\t|\tPort A\t\t|\tPort B\t\t|\tPROTCOL\t\t|\n");

    for(i = 0; i < MAX_CONVERSATIONS; i++){
        if (conversations_arr[i].src_ip.s_addr != 0)
        {
            strcpy(src_ip, inet_ntoa(conversations_arr[i].src_ip));
            strcpy(dst_ip, inet_ntoa(conversations_arr[i].dest_ip));            
            if (conversations_arr[i].proto_type == IPPROTO_TCP)
            {
                fprintf(tcp_file, "|---------------------------------------------------------------------------------------------------------------------------------------|\n");
                strncpy(p_type, "TCP", 4);
            fprintf(tcp_file, "|\t%i\t|\t%s\t|\t%s\t|\t%i\t\t|\t%i\t\t|\t%s\t\t|\n", conversations_arr[i].conv_id, src_ip, dst_ip, conversations_arr[i].src_port, conversations_arr[i].dest_port, p_type);

            }
            else if(conversations_arr[i].proto_type == IPPROTO_UDP)
            {
                fprintf(udp_file, "|---------------------------------------------------------------------------------------------------------------------------------------|\n");
                strncpy(p_type, "UDP", 4);
                fprintf(udp_file, "|\t%i\t|\t%s\t|\t%s\t|\t%i\t\t|\t%i\t\t|\t%s\t\t|\n", conversations_arr[i].conv_id, src_ip, dst_ip, conversations_arr[i].src_port, conversations_arr[i].dest_port, p_type);
            }
        }
    }
    /* EOF TCP FILE */
    fprintf(tcp_file, "+---------------------------------------------------------------------------------------------------------------------------------------+\n");
    /* EOF UDP FILE */
    fprintf(udp_file, "+---------------------------------------------------------------------------------------------------------------------------------------+\n");

    fclose(tcp_file);
    fclose(udp_file);
    free(out_filename);
}



int add_packet_to_list(packet_node_s **root, const u_char * original_packet, size_t packet_size, uint32_t id)
{
    int flag = 1, index;
    packet_node_s * node = malloc(sizeof(packet_node_s)), *temp = *root;
    if (!node)
    {
        error("failed to alloc a packet_node.");
        flag = -1;
    }
    else
    {
        node->p_id = id;
        node->next = NULL;
        node->packet_data = malloc(packet_size);
        node->packet_length = packet_size;
        for(index = 0; index < packet_size; index++)
        {
            node->packet_data[index] = original_packet[index];
        }
        if (temp != NULL)
        {
            while(temp->next != NULL)
            {
                temp = temp->next;
            }
            temp->next = node;
        }
        else
            *root = node;
    }
    return flag;
}

void print_packet_list(packet_node_s ** root, int max){
    packet_node_s * temp = *root;
    int i, index;
    while(temp != NULL)
    {
        index = temp->p_id + 1;
        printf("----------[%05i/%05i]-----------\n", index, max);
        for(i=0;i<temp->packet_length;i++)
            printf("%c", temp->packet_data[i]);
        printf("\n----------------------------------\n");
        temp = temp->next;
    }
}

void print_packets(conv_s conversations[MAX_CONVERSATIONS])
{
    int i;
    for(i = 0; i < MAX_CONVERSATIONS; i++)
    {
        if (conversations_arr[i].src_ip.s_addr != 0)
            print_packet_list(&(conversations_arr[i].packet_list), conversations_arr[i].packets_from_a_to_b+conversations_arr[i].packets_from_b_to_a);
    }
}

void free_list(packet_node_s **root) {
    packet_node_s *temp = *root, *next;
    while (temp != NULL) {
        next = temp->next;
        free(temp->packet_data); /* the alloc for the u_char packet */
        free(temp);
        temp = next;
    }
}

void free_all(conv_s conversations[MAX_CONVERSATIONS]){
    int i;
    for(i = 0; i < MAX_CONVERSATIONS; i++){
        if (conversations_arr[i].src_ip.s_addr != 0)
            free_list(&conversations[i].packet_list);
    }
}

int conversation_hash(const conv_s *conversation) {
    conv_hash_g = HASH_CONST;
    conv_hash_g ^= conversation->src_ip.s_addr; // conv_hash_g = ((conv_hash_g << 5) + conv_hash_g) ^ (conversation->src_ip.s_addr);
    conv_hash_g ^= conversation->dest_ip.s_addr; // conv_hash_g = ((conv_hash_g << 5) + conv_hash_g) ^ (conversation->dest_ip.s_addr);
    conv_hash_g ^= conversation->src_port; // conv_hash_g = ((conv_hash_g << 5) + conv_hash_g) ^ (conversation->src_port);
    conv_hash_g ^= conversation->dest_port; // conv_hash_g = ((conv_hash_g << 5) + conv_hash_g) ^ (conversation->dest_port);
    conv_hash_g ^= conversation->proto_type;
    return conv_hash_g % MAX_CONVERSATIONS;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    char ip_src_str[INET_ADDRSTRLEN], ip_dst_str[INET_ADDRSTRLEN];
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct ip *ip_header;
    conv_s conversation;
    int hash;

    ip_header = (struct ip *)(packet + ETH_HEADER_SIZE); // Skip Ethernet header
    conversation.src_ip = ip_header->ip_src;
    conversation.dest_ip = ip_header->ip_dst;
    
    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)(packet + ETH_HEADER_SIZE + (ip_header->ip_hl << 2));
        conversation.src_port = ntohs(tcp_header->th_sport);
        conversation.dest_port = ntohs(tcp_header->th_dport);
        hash = conversation_hash(&conversation);

        strncpy(ip_src_str, inet_ntoa(conversation.src_ip), INET_ADDRSTRLEN);
        strncpy(ip_dst_str, inet_ntoa(conversation.dest_ip), INET_ADDRSTRLEN);
        // okay("Processing packet: Source IP: %s, Destination IP: %s, Source Port: %u, Destination Port: %u", ip_src_str, ip_dst_str, conversation.src_port, conversation.dest_port);
        // okay("[%i]\t[%s]->[%s]:%i\t[%s]->[%s]:%i", hash, ip_src_str, ip_dst_str,(conversations[hash].src_ip.s_addr == conversation.src_ip.s_addr && conversations[hash].dest_ip.s_addr == conversation.dest_ip.s_addr), ip_src_str, ip_dst_str, (conversations[hash].src_ip.s_addr == conversation.dest_ip.s_addr && conversations[hash].dest_ip.s_addr == conversation.src_ip.s_addr));

        if ( (conversations_arr[hash].src_ip.s_addr == conversation.src_ip.s_addr && conversations_arr[hash].dest_ip.s_addr == conversation.dest_ip.s_addr) || (conversations_arr[hash].src_ip.s_addr == conversation.dest_ip.s_addr && conversations_arr[hash].dest_ip.s_addr == conversation.src_ip.s_addr) ){
            if (conversations_arr[hash].src_ip.s_addr == conversation.src_ip.s_addr) { /* if source sent it  */
                conversations_arr[hash].packets_from_a_to_b++;
            } else { /* if dest  sent it (aka dest is now source)  */
                conversations_arr[hash].packets_from_b_to_a++;
            }
            conversations_arr[hash].num_packets++;
            add_packet_to_list(&(conversations_arr[hash].packet_list),packet, pkthdr->caplen, conversations_arr[hash].num_packets - 1);
        } else {
            conversation.conv_id = conv_id_tcp_g++;
            conversations_arr[hash] = conversation;
            conversations_arr[hash].packets_from_a_to_b = 1;
            conversations_arr[hash].num_packets = 1;
            conversations_arr[hash].packets_from_b_to_a = 0;
            conversations_arr[hash].proto_type = IPPROTO_TCP;
            init_list(&(conversations_arr[hash].packet_list));
            add_packet_to_list(&(conversations_arr[hash].packet_list), packet, pkthdr->caplen, conversations_arr[hash].num_packets - 1);
            // okay("New Conversation: Source IP: %s, Destination IP: %s, Source Port: %u, Destination Port: %u", ip_src_str, ip_dst_str, conversation.src_port, conversation.dest_port);
        }
        // info("Packets from A to B: %d, Packets from B to A: %d", conversations[hash].packets_from_a_to_b, conversations[hash].packets_from_b_to_a);
    }
    else if (ip_header->ip_p == IPPROTO_UDP)
    {
        udp_header = (struct udphdr *)(packet + ETH_HEADER_SIZE + (ip_header->ip_hl << 2));
        conversation.src_port = ntohs(udp_header->uh_sport);
        conversation.dest_port = ntohs(udp_header->uh_dport);
        hash = conversation_hash(&conversation);

        strncpy(ip_src_str, inet_ntoa(conversation.src_ip), INET_ADDRSTRLEN);
        strncpy(ip_dst_str, inet_ntoa(conversation.dest_ip), INET_ADDRSTRLEN);

        if ((conversations_arr[hash].src_ip.s_addr == conversation.src_ip.s_addr && conversations_arr[hash].dest_ip.s_addr == conversation.dest_ip.s_addr) ||
            (conversations_arr[hash].src_ip.s_addr == conversation.dest_ip.s_addr && conversations_arr[hash].dest_ip.s_addr == conversation.src_ip.s_addr)) {
            if (conversations_arr[hash].src_ip.s_addr == conversation.src_ip.s_addr) { /* if source sent it  */
                conversations_arr[hash].packets_from_a_to_b++;
            } else { /* if dest sent it (aka dest is now source)  */
                conversations_arr[hash].packets_from_b_to_a++;
            }
            conversations_arr[hash].num_packets++;
            add_packet_to_list(&(conversations_arr[hash].packet_list), packet, pkthdr->caplen, conversations_arr[hash].num_packets - 1);
        } else {
            conversation.conv_id = conv_id_udp_g++;
            conversations_arr[hash] = conversation;
            conversations_arr[hash].packets_from_a_to_b = 1;
            conversations_arr[hash].num_packets = 1;
            conversations_arr[hash].packets_from_b_to_a = 0;
            conversations_arr[hash].proto_type = IPPROTO_UDP;
            init_list(&(conversations_arr[hash].packet_list));
            add_packet_to_list(&(conversations_arr[hash].packet_list), packet, pkthdr->caplen, conversations_arr[hash].num_packets - 1);
            // okay("New Conversation: Source IP: %s, Destination IP: %s, Source Port: %u, Destination Port: %u", ip_src_str, ip_dst_str, conversation.src_port, conversation.dest_port);
        }
        // info("Packets from A to B: %d, Packets from B to A: %d", conversations[hash].packets_from_a_to_b, conversations[hash].packets_from_b_to_a);
    }
}

// Save conversation data to JSON file using libjson-c
void save_to_json(const char *filename) {
    json_object *root, *conversations_array, *conversation_object;
    size_t i; FILE * fp;
    char type[4] = "\0";
    root = json_object_new_object();
    conversations_array = json_object_new_array();
    json_object_object_add(root, "conversations", conversations_array);
    for (i = 0; i < MAX_CONVERSATIONS; i++) {
        if (conversations_arr[i].src_ip.s_addr != 0) {
            if (conversations_arr[i].proto_type == IPPROTO_TCP)
                strncpy(type, "TCP", 4);
            else if (conversations_arr[i].proto_type == IPPROTO_UDP)
                strncpy(type, "UDP", 4);
            // okay("%zu is not empty.", i);
            conversation_object = json_object_new_object();
            json_object_object_add(conversation_object, "conv_id", json_object_new_int(conversations_arr[i].conv_id));
            json_object_object_add(conversation_object, "conv_type", json_object_new_string(type));
            json_object_object_add(conversation_object, "source_ip", json_object_new_string(inet_ntoa(conversations_arr[i].src_ip)));
            json_object_object_add(conversation_object, "destination_ip", json_object_new_string(inet_ntoa(conversations_arr[i].dest_ip)));
            json_object_object_add(conversation_object, "source_port", json_object_new_int(conversations_arr[i].src_port));
            json_object_object_add(conversation_object, "destination_port", json_object_new_int(conversations_arr[i].dest_port));
            json_object_object_add(conversation_object, "packets_from_a_to_b", json_object_new_int(conversations_arr[i].packets_from_a_to_b));
            json_object_object_add(conversation_object, "packets_from_b_to_a", json_object_new_int(conversations_arr[i].packets_from_b_to_a));
            /* add to main array object */
            json_object_array_add(conversations_array, conversation_object);
            strncpy(type, "", 4);
        }
    }
    fp = fopen(filename, "w"); /* dump the JSON to a file */
    fprintf(fp, "%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    fclose(fp);
    json_object_put(root);
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 3) {
        printf("Usage: %s <pcap file> <output json file>\n", argv[0]);
        return 1;
    }
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    memset(conversations_arr, 0, (sizeof(conv_s) * MAX_CONVERSATIONS));
    for (int i = 0; i < MAX_CONVERSATIONS; i++) {
        init_list(&(conversations_arr[i].packet_list));
    }
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    save_to_json(argv[2]);
    print_packets(conversations_arr);
    print_output_to_file(conversations_arr, argv[1]);
    free_all(conversations_arr);
    return 0;
}