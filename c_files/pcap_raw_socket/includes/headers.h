
/*  */
#include <linux/if_packet.h>
#include <linux/if_ether.h>

/*  */
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

/*  */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*  */
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

/*  */
#include <pcap.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

#define CAPTURE_LIMIT 5
#define CAPTURE_LIMIT_STOPABLE 1
#define MODE_PROMISC_ON 1
#define MODE_PROMISC_OFF 0
#define TIMEOUT_LIMIT 1000
#define DEVICE_NAME_LIMIT 129