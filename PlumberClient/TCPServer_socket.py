import logging
from scapy.layers.inet import Raw
import socket
import threading


class IncomingTCPSocketHandler(threading.Thread):
    def __init__(self, in_queue, out_queue, stop_event, host, port):
        super(IncomingTCPSocketHandler, self).__init__()
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.logger = logging.getLogger("TCP Server Channel")
        self.data = None
        self.conn_alive = True
        self.request = None
        self.host = host
        self.port = port

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.port))
        s.listen(1)
        while not self.stop_event.is_set():
            self.request, addr = s.accept()
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
        get_data_thread.join()
        write_data_thread.join()

    def get_data(self):
        while not self.stop_event.is_set() and self.conn_alive:
            data = self.request.recv(1024)
            if not data:
                self.conn_alive = False
                break
            self.out_queue.put(data)

    def write_data(self):
        while not self.stop_event.is_set() and self.conn_alive:
            try:
                tcp_pkt = self.in_queue.get()
                data = bytes(tcp_pkt[Raw])
                if self.conn_alive:
                    self.request.sendall(data)
                else:
                    break
            except Exception as ex:
                logging.exception("read data from in_queue failed")
                break
