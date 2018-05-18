from scapy.all import *


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
    ]
