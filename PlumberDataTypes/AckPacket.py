from PlumberPacket import PlumberPacket


class AckPacket(PlumberPacket):
    def __init__(self):
        super(PlumberPacket, self).__init__(message_type="ack")
