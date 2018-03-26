from PlumberPacket import PlumberPacket


class CloseSessionPacket(PlumberPacket):
    def __init__(self):
        super(PlumberPacket, self).__init__(message_type="close")

