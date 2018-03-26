from scapy.all import *
from scapy.layers.inet import ICMP
import threading
import logging
import struct
from Modules.DataPacket import DataPacket
from Modules.PlumberPacket import PlumberPacket


logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


def get_plumberpacket_packet(base_proto, magic, pkt):
    if base_proto in pkt and Raw in pkt:
        logging.debug("base_proto={protocol}, magic={_magic}".format(protocol=base_proto, _magic=magic))
        plum_packet = PlumberPacket(pkt[base_proto][Raw].load)
        if plum_packet.magic == magic:
            return plum_packet
    return None


class IncomingPlumberDataThread(threading.Thread):
    def __init__(self, incoming_queue, packet_filter, protocol=ICMP, magic=12345, target=None, name=None):
        super(IncomingPlumberDataThread, self).__init__()
        self.target = target
        self.name = name
        self.packet_filter_func = packet_filter
        self.protocol = protocol
        self.counter = 0
        self.magic = magic
        self.queue = incoming_queue

    def run(self):
        print "Starting " + self.name
        sniff(lfilter=self.packet_filter_func, prn=self.dissect_packet())
        print "Exiting " + self.name
        return

    def stop_filter_by_packet(self, stop_pkt):
        def stop_filter(pkt):
            if self.protocol in pkt and Raw in pkt and str(pkt[Raw].load).startswith(struct.pack("<Q", 11111)):
                return True
            else:
                return False
        return stop_filter

    def dissect_packet(self):
        def custom_action(pkt):
            if self.protocol in pkt:
                logging.debug("{0} packet! {1}".format(str(self.protocol), pkt.summary()))
                if Raw in pkt:
                    plum_pkt = get_plumberpacket_packet(self.protocol, self.magic, pkt)
                    if plum_pkt:
                        logging.debug("PlumberPacket!")
                        self.queue.put(plum_pkt)
                    else:
                        logging.debug("not plumber packet")
            else:
                logging.debug(pkt.show2())
            self.counter += 1
        return custom_action

