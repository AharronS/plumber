from scapy.all import *


class PlumberPacket(Packet):
    name = "PlumberPacket"
    fields_desc = [
        ShortField("magic", 12345),
        IntEnumField("message_target", 0, {0: "server", 1: "client"}),
        IntEnumField("message_type", 1, {1: "ack", 2: "data", 3: "start", 4: "auth", 5: "close"}),
        IPField("ip", "0.0.0.0"),
        ShortField("port", 1337),
        IntField("ack", 0),
        ShortField("port", 1337),
        ShortField("seq", 0),
        FieldLenField("len", None, length_of="data"),
        StrLenField("data", "", length_from=lambda pkt: pkt.len)
    ]
