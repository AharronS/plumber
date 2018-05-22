from PlumberPacket import PlumberPacket


"""
Poll Packet is PlumberPacket with other type field
"""


class PollPacket(PlumberPacket):
    def __init__(self):
        super(PlumberPacket, self).__init__(message_type="poll")
