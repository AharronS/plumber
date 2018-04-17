import sys
sys.path.append('../')
from scapy.all import *
from Protocol import *
from scapy.layers.inet import IP, TCP
import threading
import logging


class OutgoingDataThread(threading.Thread):
    def __init__(self, incoming_queue, outgoing_queue, protocol=TCP, target=None, name=None):
        super(OutgoingDataThread, self).__init__()
        self.target = target
        self.name = name
        self.counter = 0
        self.protocol = protocol
        self.in_queue = incoming_queue
        self.out_queue = outgoing_queue
        self.logger = logging.getLoggerClass()

    def run(self):
        while True:
            if not self.in_queue.empty():
                plumber_item = self.in_queue.get()
                self.logger.info("got plumber packet")
                self.logger.debug(plumber_item[PlumberPacket].show(dump=True))
                if plumber_item[PlumberPacket].message_type == 2:
                    self.logger.info("got Data PlumberPacket!")
                    data = self.protocol(plumber_item[PlumberPacket].data)
                    if hasattr(data, 'chksum'):
                        del data.chksum
                    data_to_send = IP(dst=plumber_item.ip)/data
                    self.logger.debug(data_to_send.show(dump=True))
                    response = sr1(data_to_send)
                    response.show()
                self.counter += 1
                time.sleep(0.001)
        return
