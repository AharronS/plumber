import sys
sys.path.append('../')
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
from Protocol import *
from Protocol.DataPacket import DataPacket
import threading
import logging
import traceback


def generate_icmp_wrapper(plumber_pkt, dst_ip):
    ip_layer = IP(dst=dst_ip)
    icmp_layer = ICMP(type="echo-request")
    return ip_layer/icmp_layer/plumber_pkt


def plumberpacket_wrapper(magic, socks_pkt):
    plumber_pkt = DataPacket()
    plumber_pkt.message_target = "server"
    plumber_pkt.data = socks_pkt
    plumber_pkt.magic = magic

    return plumber_pkt


def get_socks_packet(magic, pkt):
    if IP in pkt and Raw in pkt:
        logging.debug("base_proto={protocol}, magic={_magic}".format(protocol=TCP, _magic=magic))
        plum_packet = PlumberPacket(pkt[ICMP][Raw].load)
        if plum_packet.magic == magic:
            return plum_packet.data
    return None


class OutgoingCovertThread(threading.Thread):
    def __init__(self, out_queue, in_queue, stop_event, magic, server_ip, name=None):
        super(OutgoingCovertThread, self).__init__()
        self.target = server_ip
        self.name = name
        self.magic = magic
        self.counter = 0
        self.out_queue = out_queue
        self.in_queue = in_queue
        self.logger = logging.getLogger("Outgoing Channel")
        self.stop_event = stop_event

    def run(self):
        while not self.stop_event.is_set():
            if not self.out_queue.empty():
                try:
                    socks_pkt = self.out_queue.get()
                    self.logger.debug("got socks packet")
                    plum_pkt = plumberpacket_wrapper(self.magic, socks_pkt)
                    icmp_pkt = generate_icmp_wrapper(plum_pkt, self.target)
                    self.logger.debug("{}".format(icmp_pkt.show2(dump=True)))
                    covert_res = sr1(icmp_pkt, timeout=1000)
                    socks_res = get_socks_packet(self.magic, covert_res)
                    self.in_queue.put(socks_res)
                    self.counter += 1
                    time.sleep(0.001)
                except Exception as ex:
                    self.logger.warning("{0}".format(ex.message))
                    traceback.print_exc()
                    continue
        return
