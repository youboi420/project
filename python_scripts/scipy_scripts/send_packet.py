from scapy.all import *

ip_segment = IP(IP(dst="127.0.0.1", src="127.0.0.1"))
tcp_segment = TCP(dport=12345, sport=54321, flags="S")
data_segment = Raw(load="Hello world")

my_frame = ip_segment / tcp_segment / data_segment
send(my_frame)
# one liner
# send(IP(dst="127.0.0.1", src="127.0.0.1")/TCP(dport=12345, sport=54321, flags="S")/Raw(load="hello world"))