import sys
sys.path.append('../')
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from Protocol.DataPacket import DataPacket


# VARIABLES
dst = "188.166.148.53"
sport = random.randint(1024,65535)
dport = int(80)


# SYN
ip= IP(dst=dst)
SYN = TCP(sport=sport,dport=dport,flags='S',seq=1000)
pl_pkt = DataPacket()
pl_pkt.ip="216.58.206.46"
pl_pkt.data=SYN
pl_pkt.message_target="server"

SYNACK = sr1(ip/ICMP()/pl_pkt)

"""
ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(ip/ACK)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                

"""
# ACK
