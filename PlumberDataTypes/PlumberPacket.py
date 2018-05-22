from scapy.all import *


"""
for more information about PlumberPacket go to the documentation
"""


class PlumberPacket(Packet):
    name = "PlumberPacket"
    fields_desc = [
        # magic for identify plumber packets
        ShortField("magic", 12345),
        # packet destination
        IntEnumField("message_target", 0, {0: "server", 1: "client"}),
        # type of packets
        IntEnumField("message_type", 1, {1: "ack", 2: "data", 3: "start", 4: "auth", 5: "poll",
                                         6: "close"}),
        # destination ip
        IPField("ip", "0.0.0.0"),
        # source ip
        IPField("src_ip", "0.0.0.0"),
        # id for icmp id
        IntField("id", 0),
        # seq for icmp seq
        ShortField("seq", 0),
    ]
