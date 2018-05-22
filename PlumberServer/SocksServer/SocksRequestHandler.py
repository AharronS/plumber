import struct
from SocketServer import BaseServer, ThreadingTCPServer, StreamRequestHandler
from AddressType import AddressType
from Session import Session
from SocksMethod import SocksMethod
import logging
from SocksServerTools import close_session, host_from_ip, port_from_byte, build_command_response, byte_to_int
from CommandsExec import CommandExecutor
from ServerReply import ReplyType
from SocksCommand import SocksCommand


class Socks5RequestHandler(StreamRequestHandler):
    def __init__(self, request, client_address, server):
        StreamRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        session = Session(self.connection)
        logging.info('Create session[%s] for %s:%d' % (
            1, self.client_address[0], self.client_address[1]))
        print self.server.allowed
        if self.server.allowed and self.client_address[0] not in self.server.allowed:
            close_session(session)
            return
        client = self.connection
        client.recv(1)
        method_num, = struct.unpack('b', client.recv(1))
        methods = struct.unpack('b' * method_num, client.recv(method_num))
        auth = self.server.is_auth()
        if methods.__contains__(SocksMethod.NO_AUTHENTICATION_REQUIRED) and not auth:
            client.send(b"\x05\x00")
        elif methods.__contains__(SocksMethod.USERNAME_PASSWORD) and auth:
            client.send(b"\x05\x02")
            if not self.__do_username_password_auth():
                logging.info('Session[%d] authentication failed' % session.get_id())
                close_session(session)
                return
        else:
            client.send(b"\x05\xFF")
            return
        version, command, reserved, address_type = struct.unpack('b' * 4, client.recv(4))
        host = None
        port = None
        if address_type == AddressType.IPV4:
            ip_a, ip_b, ip_c, ip_d, p1, p2 = struct.unpack('b' * 6, client.recv(6))
            host = host_from_ip(ip_a, ip_b, ip_c, ip_d)
            port = port_from_byte(p1, p2)
        elif address_type == AddressType.DOMAIN_NAME:
            host_length, = struct.unpack('b', client.recv(1))
            host = client.recv(host_length)
            p1, p2 = struct.unpack('b' * 2, client.recv(2))
            port = port_from_byte(p1, p2)
        else:  # address type not support
            client.send(build_command_response(ReplyType.ADDRESS_TYPE_NOT_SUPPORTED))

        command_executor = CommandExecutor(host, port, session)
        if command == SocksCommand.CONNECT:
            logging.info("Session[%s] Request connect %s:%d" % (session.get_id(), host, port))
            command_executor.do_connect()
        close_session(session)

    def __do_username_password_auth(self):
        client = self.connection
        client.recv(1)
        length = byte_to_int(struct.unpack('b', client.recv(1))[0])
        username = client.recv(length)
        length = byte_to_int(struct.unpack('b', client.recv(1))[0])
        password = client.recv(length)
        user_manager = self.server.get_user_manager()
        if user_manager.check(username, password):
            client.send(b"\x01\x00")
            return True
        else:
            client.send(b"\x01\x01")
            return False
