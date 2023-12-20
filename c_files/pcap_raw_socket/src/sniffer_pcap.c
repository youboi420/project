#include "../includes/my_utils.h"

int main()
{
    char filename[] = "test.pcap";
    pcap_t * handle; pcap_dumper_t *pcap_dumper;

    setup_device_file(&pcap_dumper, &handle, filename);
    set_non_blocking_mode();
    stopable_capture(handle, CAPTURE_LIMIT, main_packet_handler, pcap_dumper);
    /* below is a non-stoppable packet capture*/
    /* pcap_loop(handle, CAPTURE_LIMIT, main_packet_handler, (unsigned char *)pcap_dumper); */
    pcap_dump_close(pcap_dumper);
    pcap_close(handle);
    return EXIT_SUCCESS;
}