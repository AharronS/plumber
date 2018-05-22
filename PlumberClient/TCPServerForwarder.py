import logging
from scapy.layers.inet import Raw
import socket
import threading


"""
Incoming Tcp Data thread - 
The role of the thread is server as TCP Server,
when the server accept connection, get data from socket and put the data on the out_queue
when the covert channel get data from proxy server return the data to the socks client
"""


class IncomingTCPSocketHandler(threading.Thread):
    def __init__(self, in_queue, out_queue, stop_event, host, port):
        super(IncomingTCPSocketHandler, self).__init__()
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.logger = logging.getLogger("TCP Server Channel")
        self.name = "TCP Server Channel"
        self.data = None
        self.conn_alive = True
        self.request = None
        self.host = host
        self.port = port

    def stop(self):
        self.stop_event.set()

    def stopped(self):
        return self.stop_event.is_set()

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # reuse socket for multiple connections
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(5)
        while not self.stop_event.is_set():
            self.request, addr = s.accept()
            self.conn_alive = True
            # handle tcp connection
            self.handle(addr)
            self.request.close()
            self.logger.debug("server close connection")

    def handle(self, addr):
        self.logger.debug("got connection from {}".format(addr))
        get_data_thread = threading.Thread(target=self.get_data)
        write_data_thread = threading.Thread(target=self.write_data)
        get_data_thread.daemon = True
        write_data_thread.daemon = True
        get_data_thread.start()
        write_data_thread.start()
        write_data_thread.join()
        get_data_thread.join()

    def get_data(self):
        try:
            while not self.stop_event.is_set() and self.conn_alive:
                try:
                    data = self.request.recv(1024)
                    if not data:
                        self.conn_alive = False
                        break
                    self.out_queue.put(data)
                except:
                    self.logger.exception("data receive failed")
        except Exception as ex:
            self.logger.exception("get data exception")
        self.conn_alive = False

    def write_data(self):
        try:
            while not self.stop_event.is_set() and self.conn_alive:
                if not self.in_queue.empty():
                    try:
                        tcp_pkt = self.in_queue.get()
                        data = bytes(tcp_pkt[Raw])
                        if self.conn_alive:
                            self.request.sendall(data)
                    except Exception as ex:
                        logging.exception("read data from in_queue failed")
        except:
            self.logger.exception("write data exception")
