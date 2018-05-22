class ServerReply(object):
    def __init__(self, value):
        self.__value = value

    def get_byte_string(self):
        if self.__value == 0:
            return b'\x00'
        elif self.__value == 1:
            return b'\x01'
        elif self.__value == 2:
            return b'\x02'
        elif self.__value == 3:
            return b'\x03'
        elif self.__value == 4:
            return b'\x04'
        elif self.__value == 5:
            return b'\x05'
        elif self.__value == 6:
            return b'\x06'
        elif self.__value == 7:
            return b'\x07'
        elif self.__value == 8:
            return b'\x08'

    def get_value(self):
        return self.__value


class ReplyType(object):
    SUCCEEDED = ServerReply(0)
    GENERAL_SOCKS_SERVER_FAILURE = ServerReply(1)
    CONNECTION_NOT_ALLOWED_BY_RULESET = ServerReply(2)
    NETWORK_UNREACHABLE = ServerReply(3)
    HOST_UNREACHABLE = ServerReply(4)
    CONNECTION_REFUSED = ServerReply(5)
    TTL_EXPIRED = ServerReply(6)
    COMMAND_NOT_SUPPORTED = ServerReply(7)
    ADDRESS_TYPE_NOT_SUPPORTED = ServerReply(8)
