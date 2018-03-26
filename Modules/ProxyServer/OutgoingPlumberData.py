from scapy.all import *
from scapy.layers.inet import IP, ICMP
import threading
import logging
from Modules.PlumberPacket import PlumberPacket
from Modules.PlumberPacket import PlumberPacket


logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


class OutgoingPlumberThread(threading.Thread):
    def __init__(self, incoming_queue, protocol=ICMP, target=None, name=None):
        super(OutgoingPlumberThread, self).__init__()
        self.target = target
        self.name = name
        self.counter = 0
        self.protocol = protocol
        self.in_queue = incoming_queue
        return

    def run(self):
        while True:
            if not self.in_queue.empty():
                plumber_item = self.in_queue.get()
                logging.debug("got plumber outgoing packet")
                plumber_item[PlumberPacket].show()
                data = IP(dst=plumber_item)/ICMP(type=0)/plumber_item
                data.show()
                send(data)
                time.sleep(0.001)
        return
