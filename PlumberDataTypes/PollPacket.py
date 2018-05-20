from PlumberPacket import PlumberPacket


class PollPacket(PlumberPacket):
    def __init__(self):
        super(PlumberPacket, self).__init__(message_type="poll")
