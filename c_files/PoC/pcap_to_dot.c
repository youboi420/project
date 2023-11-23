/*
when going to windows...
(ill probably pack my own and upload it to github to install the dependency more easliy)
install npcap
install the correct lib to properties and includes to the project settings
move the dll to the lib dir and then change the file name to (yourfilename.pcpa)
*/

#include <stdio.h>
#include <pcap.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("file.pcap", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening PCAP file: %s\n", errbuf);
        return 1;
    }

    // Create a DOT file
    FILE *dotFile = fopen("network_traffic.dot", "w");
    if (dotFile == NULL) {
        perror("Error creating DOT file");
        return 1;
    }

    // Write DOT file header
    fprintf(dotFile, "digraph NetworkTraffic {\n");

    // Loop through packets and process them
    pcap_loop(handle, 0, packet_handler, dotFile);

    // Write DOT file footer
    fprintf(dotFile, "}\n");

    fclose(dotFile);

    // Close the PCAP handle
    pcap_close(handle);

    // Use Graphviz to render the DOT file into an image
    // system("dot -Tpng network_traffic.dot -o network_traffic.png");

    return 0;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    FILE *dotFile = (FILE *)user;

    // Extract packet information as needed
    // For simplicity, let's assume you have source and destination IP addresses
    char srcIP[16], destIP[16];
    // char msg[1024];
    // snprintf(msg, sizeof(msg), "%s", packet);
    snprintf(srcIP, sizeof(srcIP), "%d.%d.%d.%d", packet[26], packet[27], packet[28], packet[29]);
    snprintf(destIP, sizeof(destIP), "%d.%d.%d.%d", packet[30], packet[31], packet[32], packet[33]);
    // Write DOT representation for the packet
    fprintf(dotFile, "\"%s\" -> \"%s\" [label=\"info\"];\n", srcIP, destIP);
}