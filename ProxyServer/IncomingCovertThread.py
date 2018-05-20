import sys
sys.path.append('../')
from scapy.all import *
from Protocol import *
from scapy.layers.inet import IP, ICMP, TCP
import threading
import logging


def get_plumberpacket_packet(magic, pkt):
    if IP in pkt and ICMP in pkt and Raw in pkt:
        plum_packet = PlumberPacket(pkt[ICMP][Raw].load)
        if plum_packet.magic == magic:
            plum_packet.src_ip = pkt[IP].src
            plum_packet.id, plum_packet.seq = pkt[ICMP].id, pkt[ICMP].seq
            return plum_packet
        else:
            raise Exception("Not PlumberPacket!")


def stop_sniff(pkt):
    if ICMP in pkt and pkt[ICMP].id == 11111 and pkt[ICMP].seq == 11111:
        logging.debug("stop filter!\n" + pkt.summary())
        return True
    else:
        return False


class IncomingCovertDataThread(threading.Thread):
    def __init__(self, incoming_queue, packet_filter, stop_event, protocol=ICMP, magic=12345,
                 target=None, name=None):
        super(IncomingCovertDataThread, self).__init__()
        self.target = target
        self.name = name
        self.packet_filter_func = packet_filter
        self.protocol = protocol
        self.counter = 0
        self.magic = magic
        self.in_queue = incoming_queue
        self.logger = logging.getLogger("incomming")
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
                self.logger.debug("incoming packet:\n{}".format(pkt.show2(dump=True)))
                if Raw in pkt:
                    try:
                        plum_pkt = get_plumberpacket_packet(self.magic, pkt)
                        self.logger.info("incoming PlumberPacket!")
                        self.in_queue.put(plum_pkt)
                    except Exception as ex:
                        self.logger.exception("unknown packet")
                        return custom_action
            else:
                self.logger.debug("unknown protocol: \n" + pkt.show(dump=True))
            self.counter += 1
        return custom_action
