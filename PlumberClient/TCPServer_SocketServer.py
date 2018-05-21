import SocketServer, time, select, sys
import logging
from scapy.layers.inet import Raw
import socket
import threading
import Queue
from threading import Thread


class SimpleServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, in_queue, out_queue, stop_event):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.logger = logging.getLogger("TCP Server Channel")


class SimpleRequestHandler(SocketServer.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        ready_to_read, ready_to_write, in_error = select.select([self.request], [], [], None)
        done = False
        while not done:
            if len(ready_to_read) == 1 and ready_to_read[0] == self.request:
                data = self.request.recv(1024)
                if not data:
                    break
                elif len(data) > 0:
                    self.server.out_queue.put(data)

                tcp_pkt = '1'
                while tcp_pkt:
                    if not self.server.in_queue.empty():
                        try:
                            tcp_pkt = self.server.in_queue.get()
                            data = bytes(tcp_pkt[Raw])
                            self.request.send(data)
                        except Exception as ex:
                            logging.exception("read data from in_queue failed")
                            break
                    else:
                        break

        self.request.close()
#
# if __name__ == '__main__':
#     server = SimpleServer(('', 7000), SimpleRequestHandler,
#                           SimpleCommandProcessor(), 'Welcome to the SimpleServer.\n\r')
#
#     try:
#         server.serve_forever()
#     except KeyboardInterrupt:
#         sys.exit(0)
