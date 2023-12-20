#include "../includes/my_utils.h"

int create_raw_socket()
    {
    int raw_sock, check;

    raw_sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if( raw_sock < 0 ){
        printf("error getting raw_socket\n");
        return -1;
    }
    return raw_sock;
}

void set_non_blocking_mode()
{
    struct termios ttystate;
    // Get the terminal state
    tcgetattr(STDIN_FILENO, &ttystate);
    // Turn off canonical mode and echo
    ttystate.c_lflag &= ~(ICANON | ECHO);
    // Set non-blocking mode
    ttystate.c_cc[VMIN] = 0;
    ttystate.c_cc[VTIME] = 0;
    // Apply the changes
    tcsetattr(STDIN_FILENO, TCSANOW, &ttystate);
}

void stopable_capture(pcap_t *handle, int capture_limit, pcap_handler packet_handler, void *user_data)
{
    int ch, total = 0;
    while (1) {
        if (total >= CAPTURE_LIMIT) break;
        if (my_kbhit())
        {
            ch = getchar();
            if (ch == 's' || ch == 'S')
            {
                okay("Stopping capture. Closing file and exiting.\n");
                return; /* to exit... */
            }
        }
        total++;
        pcap_dispatch(handle, CAPTURE_LIMIT_STOPABLE, packet_handler, user_data);
        okay("capturing packet [%i/%i]...\n", total, CAPTURE_LIMIT);
    }
}

int my_kbhit()
{
    struct timeval tv; fd_set fds;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
    return FD_ISSET(STDIN_FILENO, &fds);
}

void main_packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    pcap_dumper_t *pcap_dumper = (pcap_dumper_t *)user_data;
    okay("packet captured, length: %d\n", pkthdr->len);
    pcap_dump(user_data, pkthdr, packet); /* write the packet to the pcap file in pcap format using the data  */
}

void setup_device_file(pcap_dumper_t **pcap_dumper, pcap_t ** handle, char filename[])
{
    char err_msg[PCAP_ERRBUF_SIZE], *device;
    int i = 0, device_count = 0, ch; pcap_if_t *alldevs, *dev;

    if (pcap_findalldevs(&alldevs, err_msg) == -1)
    {
        error("%s", err_msg);
        exit_prog("error finding a network device");
    }
    /*
    // for (dev = alldevs; dev; dev = dev->next)
    //     okay("%d. %s\n", ++i, dev->name);
    // for (dev = alldevs, i = 0; i < device_count - 1; dev = dev->next, i++);
    // device_count = 0;
    */
    dev = alldevs;
    device = malloc(strlen(dev->name) + 1);
    if (device != NULL)
        strcpy(device, dev->name);
    pcap_freealldevs(alldevs);
    if (device == NULL) /* no device found */
    {
        error("%s", err_msg);
        exit_prog("error finding a network device");
    }
    *handle = pcap_open_live(device, BUFSIZ, MODE_PROMISC_ON, TIMEOUT_LIMIT, err_msg);
    if (handle == NULL)
    {
        error("%s", err_msg);
        exit_prog("error opening device");
    }
    *pcap_dumper = pcap_dump_open(*handle, filename);
    if (*pcap_dumper == NULL)
    {    
        error("file: %s", filename);
        exit_prog("error opening pcap file");
    }
}

void exit_prog(char err_msg[])
{
	error("{%s}\n", err_msg);
	exit(EXIT_FAILURE);
}