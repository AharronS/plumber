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


def plumberpacket_wrapper(magic, tcp_pkt):
    plumber_pkt = DataPacket()
    plumber_pkt.message_target = "server"
    plumber_pkt.data = tcp_pkt
    plumber_pkt.magic = magic
    return plumber_pkt


def get_plumberpacket_packet(magic, pkt):
    if IP in pkt and ICMP in pkt and Raw in pkt:
        logging.debug("base_proto={protocol}, magic={_magic}".format(protocol=base_proto, _magic=magic))
        plum_packet = PlumberPacket(pkt[ICMP][Raw].load)
        if plum_packet.magic == magic:
            plum_packet.src_ip = pkt[IP].src
            plum_packet.id, plum_packet.seq = pkt[ICMP].id, pkt[ICMP].seq
            return plum_packet
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
                    tcp_packet = self.out_queue.get()
                    plum_pkt = plumberpacket_wrapper(self.magic, tcp_packet)
                    icmp_pkt = generate_icmp_wrapper(plum_pkt, self.target)
                    self.logger.debug("send icmp: {}".format(icmp_pkt.summary()))
                    covert_res = sr1(icmp_pkt, timeout=1000)
                    self.logger.debug("response icmp: {}".format(covert_res.show2(dump=True)))
                    plum_pkt = get_plumberpacket_packet(self.magic, covert_res)
                    if plum_pkt is not None:
                        self.in_queue.put(plum_pkt.data)
                        self.counter += 1
                except Exception as ex:
                    self.logger.warning("{0}".format(ex.message))
                    traceback.print_exc()
                    continue
        return
