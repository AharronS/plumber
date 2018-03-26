from PlumberPacket import PlumberPacket


class AuthPacket(PlumberPacket):
    def __init__(self):
        super(PlumberPacket, self).__init__(message_type="auth")