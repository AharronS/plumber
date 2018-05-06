
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP

class PlumberPacket(Packet):
    name = "PlumberPacket"
    fields_desc = [
        ShortField("magic", 12345),
        IntEnumField("message_target", 0, {0: "server", 1: "client"}),
        IntEnumField("message_type", 1, {1: "ack", 2: "data", 3: "start", 4: "auth", 5: "close"}),
        IPField("ip", "0.0.0.0"),
        IPField("src_ip", "0.0.0.0"),
        IntField("id", 0),
        ShortField("seq", 0),
        FieldLenField("len", None, length_of="data"),
        StrLenField("data", "", length_from=lambda pkt: pkt.len)
    ]


class DataPacket(PlumberPacket):
    def __init__(self):
        super(PlumberPacket, self).__init__(message_type="data")


def send_kill_packet(dst_addr="188.166.148.53"):
    pkt = IP(dst=dst_addr) / ICMP(id=11111, seq=11111)
    send(pkt)


def get_plumber(pkt):
    return PlumberPacket(pkt[Raw])

# VARIABLES
dst_addr = "188.166.148.53"
sport = random.randint(1024,65535)
dport = int(80)


# SYN
ip= IP(dst=dst_addr)
SYN = TCP(sport=sport, dport=dport, flags='S', seq=1000)
pl_pkt = DataPacket()
pl_pkt.ip="216.58.206.46"
pl_pkt.data=SYN[TCP]
pl_pkt.message_target="server"

SYNACK = sr1(ip/ICMP()/pl_pkt)

"""
ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(ip/ACK)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                

"""
# ACK
