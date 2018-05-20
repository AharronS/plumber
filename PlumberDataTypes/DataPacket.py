from PlumberPacket import PlumberPacket


class DataPacket(PlumberPacket):
    def __init__(self):
        super(PlumberPacket, self).__init__(message_type="data")
