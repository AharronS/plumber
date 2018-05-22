class Session(object):
    index = 0

    def __init__(self, client_socket):
        Session.index += 1
        self.__id = Session.index
        self.__client_socket = client_socket
        self._attr = {}

    def get_id(self):
        return self.__id

    def set_attr(self, key, value):
        self._attr[key] = value

    def get_client_socket(self):
        return self.__client_socket
