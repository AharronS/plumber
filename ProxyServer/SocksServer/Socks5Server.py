from ..SocksServer import *


class Socks5Server(ThreadingTCPServer):
    """
    SOCKS5 proxy server
    """

    def __init__(self, port, auth=False, user_manager=UserManager(), allowed=None):
        ThreadingTCPServer.__init__(self, ('', port), Socks5RequestHandler)
        self.__port = port
        self.__users = {}
        self.__auth = auth
        self.__user_manager = user_manager
        self.__sessions = {}
        self.allowed = allowed

    def serve_forever(self, poll_interval=0.5):
        logging.info("Create SOCKS5 server at port %d" % self.__port)
        ThreadingTCPServer.serve_forever(self, poll_interval)

    def finish_request(self, request, client_address):
        BaseServer.finish_request(self, request, client_address)

    def is_auth(self):
        return self.__auth

    def set_auth(self, auth):
        self.__auth = auth

    def get_all_managed_session(self):
        return self.__sessions

    def get_bind_port(self):
        return self.__port

    def get_user_manager(self):
        return self.__user_manager

    def set_user_manager(self, user_manager):
        self.__user_manager = user_manager