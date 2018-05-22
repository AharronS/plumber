from ..SocksServer import *
from socket import socket, AF_INET, SOCK_STREAM
import logging


class CommandExecutor(object):
    def __init__(self, remote_server_host, remote_server_port, session):
        self.__proxy_socket = socket(AF_INET, SOCK_STREAM)
        self.__remote_server_host = remote_server_host
        self.__remote_server_port = remote_server_port
        self.__client = session.get_client_socket()
        self.__session = session

    def do_connect(self):
        """
        Do SOCKS CONNECT method
        :return: None
        """
        result = self.__proxy_socket.connect_ex(self.__get_address())
        if result == 0:
            self.__client.send(build_command_response(ReplyType.SUCCEEDED))
            socket_pipe = SocketPipe(self.__client, self.__proxy_socket)
            socket_pipe.start()
            while socket_pipe.is_running():
                pass
        elif result == 60:
            self.__client.send(build_command_response(ReplyType.TTL_EXPIRED))
        elif result == 61:
            self.__client.send(build_command_response(ReplyType.NETWORK_UNREACHABLE))
        else:
            logging.error('Connection Error:[%s] is unknown' % result)
            self.__client.send(build_command_response(ReplyType.NETWORK_UNREACHABLE))

    def do_bind(self):
        pass

    def do_udp_associate(self):
        pass

    def __get_address(self):
        return self.__remote_server_host, self.__remote_server_port
