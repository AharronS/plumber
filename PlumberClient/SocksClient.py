from __future__ import division, absolute_import, print_function, unicode_literals
import sys
sys.path.append('../')
import secretsocks
from scapy.layers.inet import Raw
import Queue
range = xrange


def get_socks_data(plum_pkt):
    return bytes(plum_pkt[Raw])


class Client(secretsocks.Client):
    def __init__(self, stop_event, in_queue, out_queue):
        secretsocks.Client.__init__(self)
        self.stop_event = stop_event
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.start()

    # Receive data from our data channel and push it to the receive queue
    def recv(self):
        while not self.stop_event.is_set():
            try:
                incoming_plum = self.in_queue.get(timeout=5)
                self.recvbuf.put(get_socks_data(incoming_plum))
            except Queue.Empty:
                continue

    # Take data from the write queue and send it over our data channel
    def write(self):
        while not self.stop_event.is_set():
            try:
                outgoing_socks = self.writebuf.get(timeout=10)
            except Queue.Empty:
                continue
            self.out_queue.put(outgoing_socks)

