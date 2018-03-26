from scapy.all import *
from Protocol import *
from scapy.layers.inet import IP, ICMP, TCP
import threading
import time
import logging
import Queue
import struct


def get_plumberpacket_packet(base_proto, magic, pkt):
    if base_proto in pkt and Raw in pkt:
        logging.debug("base_proto={protocol}, magic={_magic}".format(protocol=base_proto, _magic=magic))
        plum_packet = PlumberPacket(pkt[base_proto][Raw].load)
        if plum_packet.magic == magic:
            return plum_packet
    return None


class IncomingDataThread(threading.Thread):
    def __init__(self, packet_filter, protocol=ICMP, magic=12345, target=None, name=None):
        super(IncomingDataThread, self).__init__()
        self.target = target
        self.name = name
        self.packet_filter_func = packet_filter
        self.protocol = protocol
        self.counter = 0
        self.magic = magic

    def run(self):
        print "Starting " + self.name
        sniff(lfilter=self.packet_filter_func, prn=self.dissect_packet(), stop_filter=self.stop_filter)
        print "Exiting " + self.name
        return

    @staticmethod
    def stop_filter(pkt):
        if ICMP in pkt and Raw in pkt and str(pkt[Raw].load).startswith(struct.pack("<Q", 11111)):
            return True
        else:
            return False

    def dissect_packet(self):
        def custom_action(pkt):
            if self.protocol in pkt:
                logging.debug("{0} packet! {1}".format(str(self.protocol), pkt.summary()))
                if Raw in pkt:
                    plum_pkt = get_plumberpacket_packet(self.protocol, self.magic, pkt)
                    if plum_pkt:
                        logging.debug("PlumberPacket!")
                        q1.put(plum_pkt)
                    else:
                        logging.debug("not plumber packet")
            else:
                logging.debug(pkt.show2())
            self.counter += 1
        return custom_action