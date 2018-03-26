from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading
import logging
from Modules.DataPacket import DataPacket
from Modules.PlumberPacket import PlumberPacket

logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


class OutgoingDataThread(threading.Thread):
    def __init__(self, incoming_queue, outgoing_queue, protocol=TCP, target=None, name=None):
        super(OutgoingDataThread, self).__init__()
        self.target = target
        self.name = name
        self.counter = 0
        self.protocol = protocol
        self.in_queue = incoming_queue
        self.out_queue = outgoing_queue
        return

    def run(self):
        while True:
            if not self.in_queue.empty():
                plumber_item = self.in_queue.get()
                logging.debug("got plumber packet")
                plumber_item[Protocol.PlumberPacket].show()
                if plumber_item[Protocol.PlumberPacket].message_type == 2:
                    logging.debug("got Data PlumberPacket!")
                    data = self.protocol(plumber_item[Protocol.PlumberPacket].data)
                    data.show()
                    data_to_send = IP(dst=plumber_item.ip)/data
                    data_to_send.show()
                    response = sr1(data_to_send)
                    Protocol.DataPacket(data=response)
                    self.out_queue.put()
                self.counter += 1
                time.sleep(0.001)
        return
