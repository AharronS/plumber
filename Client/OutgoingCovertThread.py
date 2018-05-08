import sys
sys.path.append('../')
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
import threading
import logging
import traceback


def generate_icmp_wrapper(plumber_pkt):
    ip_layer = IP(src=plumber_pkt.src_ip, dst=plumber_pkt.ip)
    icmp_layer = ICMP(type="echo-reply")
    icmp_layer.id, icmp_layer.seq = plumber_pkt.id, plumber_pkt.seq
    plumber_pkt.message_target = "client"
    return ip_layer/icmp_layer/plumber_pkt


class OutgoingCovertThread(threading.Thread):
    def __init__(self, incoming_queue, stop_event, protocol=TCP, target=None, name=None):
        super(OutgoingCovertThread, self).__init__()
        self.target = target
        self.name = name
        self.counter = 0
        self.protocol = protocol
        self.in_queue = incoming_queue
        self.logger = logging.getLogger("Covert response")
        self.stop_event = stop_event

    def run(self):
        while not self.stop_event.is_set():
            if not self.in_queue.empty():
                try:
                    res_pkt = self.in_queue.get()
                    logging.info("got packet")
                    logging.debug(res_pkt.show(dump=True))
                    if res_pkt.data:
                        out_pkt = generate_icmp_wrapper(res_pkt)
                    else:
                        self.logger.warning("weird packet" + res_pkt.show(dump=True))
                        continue
                    self.logger.debug("sending plumber packet response to client:{0}".format(
                        out_pkt.show2(dump=True)
                    ))
                    send(out_pkt)
                    self.counter += 1
                    time.sleep(0.001)
                except Exception as ex:
                    self.logger.warning("{0}".format(ex.message))
                    traceback.print_exc()
                    continue
        return
