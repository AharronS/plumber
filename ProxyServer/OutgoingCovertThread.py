import sys
sys.path.append('../')
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
import threading
import logging


def generate_icmp_wrapper(dst_ip, plumber_pkt):
    ip_layer = IP(dst=dst_ip)
    icmp_layer = ICMP(type="echo-reply")
    return ip_layer/icmp_layer/plumber_pkt


class OutgoingCovertThread(threading.Thread):
    def __init__(self, incoming_queue, protocol=TCP, target=None, name=None):
        super(OutgoingCovertThread, self).__init__()
        self.target = target
        self.name = name
        self.counter = 0
        self.protocol = protocol
        self.in_queue = incoming_queue

    def run(self):
        while True:
            if not self.in_queue.empty():
                res_pkt = self.in_queue.get()
                logging.info("got packet")
                logging.debug(res_pkt.show(dump=True))
                if TCP in res_pkt or UDP in res_pkt:
                    out_pkt = generate_icmp_wrapper(self.target, res_pkt)
                else:
                    continue
                send(out_pkt)
                self.counter += 1
                time.sleep(0.001)
        return
