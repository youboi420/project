from scapy.all import *
# Create a list of packets
packets = []
# Generate some example packets
for i in range(200):
    # Create an Ethernet frame with an IPv4 packet
    eth_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF")
    ip_packet = IP(src="192.168.1.1", dst="10.0.0.1")
    packet = 0
    if (i % 2 == 0):
        tcp_packet = TCP(sport=12345, dport=80)
        data = "This is some dummy data for packet {}".format(i)
        packet = eth_packet / ip_packet / tcp_packet / data
    else:
        udp_packet = UDP(sport=12345, dport=80)
        data = "This is some dummy data for packet {}".format(i)
        packet = eth_packet / ip_packet / udp_packet / data    
    # Append the packet to the list
    packets.append(packet)
# Write the packets to a PCAP file
wrpcap("file.pcap", packets)