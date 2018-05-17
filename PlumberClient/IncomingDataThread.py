import sys
sys.path.append('../')
from scapy.all import *
from Protocol import *
from scapy.layers.inet import IP, ICMP, TCP
import threading
import logging


def get_plumberpacket_packet(base_proto, magic, pkt):
    if IP in pkt and base_proto in pkt and Raw in pkt:
        logging.debug("base_proto={protocol}, magic={_magic}".format(protocol=base_proto, _magic=magic))
        plum_packet = PlumberPacket(pkt[base_proto][Raw].load)
        if plum_packet.magic == magic:
            plum_packet.src_ip = pkt[IP].src
            plum_packet.id, plum_packet.seq = pkt[ICMP].id, pkt[ICMP].seq
            return plum_packet
    return None


def stop_sniff(pkt):
    if ICMP in pkt and pkt[ICMP].id == 11111 and pkt[ICMP].seq == 11111:
        logging.debug("stop filter!\n" + pkt.summary())
        return True
    else:
        return False


class IncomingDataThread(threading.Thread):
    def __init__(self, out_queue, packet_filter, stop_event, protocol=TCP,
                 target=None, name="TCPThread"):
        super(IncomingDataThread, self).__init__()
        self.target = target
        self.name = name
        self.packet_filter_func = packet_filter
        self.protocol = protocol
        self.counter = 0
        self.queue = out_queue
        self.logger = logging.getLogger("IncomingData")
        self.stop_event = stop_event

    def run(self):
        print "Starting " + self.name
        sniff(lfilter=self.packet_filter_func, prn=self.dissect_packet(), stop_filter=stop_sniff)
        self.stop_event.set()
        print "Exiting " + self.name
        return

    def dissect_packet(self):
        def custom_action(pkt):
            if self.protocol in pkt:
                if TCP in pkt:
                    try:
                        tcp_pkt = pkt[self.protocol]
                        self.logger.debug("{}\nput on out queue.".format(tcp_pkt.summary()))
                        self.queue.put(tcp_pkt)
                    except Exception, ex:
                        self.logger.exception("TCP Packet Error")
            self.counter += 1
        return custom_action
