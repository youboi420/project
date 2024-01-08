// #include "../includes/tcp_conv.h"

// tcp_conversation_t *find_or_create_conversation(struct tcphdr *tcp_header, struct ip * ip_header)
// {
//     ENTRY e, *ep;
//     tcp_conversation_t key;
//     tcp_conversation_t *conversation;
//     // inet_ntoa
//     strncpy(key.src_ip, inet_ntoa(ip_header->ip_src), MAX_HOST_LEN);
//     strncpy(key.dst_ip, inet_ntoa(ip_header->ip_dst), MAX_HOST_LEN);
//     key.src_port = tcp_header->th_sport;
//     key.dst_port = tcp_header->th_dport;
//     key.avg_rtt = 
    

//     e.key = &key;
//     ep = hsearch(e, FIND);
//     if (ep) {
//         return (tcp_conversation_t *)ep->data;
//     } else {
//         conversation = (tcp_conversation_t *)malloc(sizeof(tcp_conversation_t));


        
//         e.data = conversation;
//         hsearch(e, ENTER);
//         return conversation;
//     }
// }