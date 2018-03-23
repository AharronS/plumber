import struct
import binascii
from sys import byteorder
from ctypes import c_uint16, c_ubyte, c_ulong


class PlumberProtocol(object):
    def __init__(self):
        self.magic = c_uint16()  # unsigned short - H
        self.message_target =   # unsigned char - B
        self.message_type = 0  # unsigned char - B
        self.ip = 0  # unsigned int - I
        self.port = 0  # unsigned short -H
        self.ack = 0  # unsigned int - I
        self.seq = 0  # unsigned short - H
        self.data_length = 0  # unsigned int - I
        self.data = None


    def get_byte_order(self):
        return byteorder

