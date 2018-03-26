import struct
import netaddr
from __builtin__ import staticmethod
import sys
from ctypes import c_uint16, c_ubyte, c_ulong
from enum import Enum
from scapy.all import *

class MessageType(Enum):
    ack = 1
    data = 2
    session_req = 3
    auth_req = 4
    close_session = 5


class PlumberPacket(object):
    def __init__(self):
        self.magic = c_uint16(12345).value  # unsigned short - H - maybe constant?
        self.message_target = c_ubyte(1).value  # unsigned char - B - 1 to server, 0 to client
        self.message_type = c_ubyte(1).value  # unsigned char - B
        self.ip = c_ulong(11).value  # unsigned int - I
        self.port = c_uint16(11).value  # unsigned short -H
        self.ack = c_ulong(11).value  # unsigned int - I
        self.seq = c_uint16(11).value  # unsigned short - H
        self.data_length = c_ulong(11).value  # unsigned int - I
        self.data = None

    # TODO: complete this function
    def pack_proto_pcaket(self):
        packed_data_headers = struct.pack("HBBIHIHI", self.magic, self.message_target, self.message_type,
                                          self.ip, self.port, self.ack, self.seq, self.data_length)
        return packed_data_headers

    def set_proto_data(self, binary_data):
        self.data = binary_data
        binary_data_len = len(binary_data)
        self.validate_struct_type(binary_data_len, "ulong")
        self.data_length = binary_data_len

    def set_message_type(self, is_for_server):
        if is_for_server is True:
            self.message_target = 1
        elif is_for_server is False:
            self.message_target = 0
        else:
            ValueError("type should be boolean")

    def set_ip_addr(self, ip_addr):
        if isinstance(ip_addr, str):
            self.ip = self.ip_to_ulong(ip_addr)
        elif isinstance(ip_addr, int):
            self.ip = self.ulong_to_ip(ip_addr)
        else:
            ValueError("ipaddr should be string or int")

    def set_message_type(self, type):
        if isinstance(type, MessageType):
            self.message_type = type.value
        else:
            raise ValueError()

    @staticmethod
    def get_byte_order():
        return sys.byteorder

    @staticmethod
    def ip_to_ulong(str_ip_address):
        return int(netaddr.IPAddress(str_ip_address))

    @staticmethod
    def ulong_to_ip(ulong_ip_address):
        return str(netaddr.IPAddress(ulong_ip_address))

    @staticmethod
    def validate_struct_type(value, struct_type):
        struct_types = {
            "uint16": "H",
            "ubyte": "B",
            "ulong": "I"
        }

        if struct_type in struct_types:
            struct.pack(struct_types[struct_type], value)
        else:
            raise ValueError("unrecognized type")


class PlumberScapyPacket(Packet):
    name = "PlumberPacket"
    fields_desc = [
        SignedShortField("magic", 12345),
        ByteField("message_target", 0),
        IntEnumField("message_type", 1, {1: "a", 2: "b"}),
        IPField("ip", "0.0.0.0"),
        SignedShortField("port", 1337),
        IntField("ack", 0),
        SignedShortField("port", 1337),
        SignedShortField("seq", 0),
        FieldLenField("len", None, length_of="data"),
        StrLenField("data", "", length_from=lambda pkt: pkt.len)
    ]
