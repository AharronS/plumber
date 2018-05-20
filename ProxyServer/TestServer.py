import sys
sys.path.append('../')
from scapy.all import *
from PlumberDataTypes import *
from scapy.layers.inet import IP, ICMP, TCP
import threading
import time
import logging
import Queue
import struct

logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )

BUF_SIZE = 100
q1 = Queue.Queue(BUF_SIZE)
q2 = Queue.Queue(BUF_SIZE)


def get_plumberpacket_packet(base_proto, magic, pkt):
    if base_proto in pkt and Raw in pkt:
        logging.debug("base_proto={protocol}, magic={_magic}".format(protocol=base_proto, _magic=magic))
        plum_packet = PlumberPacket(pkt[base_proto][Raw].load)
        if plum_packet.magic == magic:
            return plum_packet
    return None


class IncomingDataThread(threading.Thread):
    def __init__(self, incoming_queue, packet_filter, protocol=ICMP, magic=12345, target=None, name=None):
        super(IncomingDataThread, self).__init__()
        self.target = target
        self.name = name
        self.packet_filter_func = packet_filter
        self.protocol = protocol
        self.counter = 0
        self.magic = magic
        self.queue = incoming_queue

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
                        logging.info("incoming PlumberPacket!")
                        self.queue.put(plum_pkt)
                    else:
                        logging.debug("not plumber packet")
            else:
                logging.debug(pkt.show2())
            self.counter += 1
        return custom_action

if __name__ == '__main__':
    p = IncomingDataThread(incoming_queue=q1, name='icmp interpreter', packet_filter=lambda x: (x.haslayer(IP) and
                                                                             x.haslayer(ICMP) and
                                                                             x.getlayer(ICMP).type == 8))

    c = OutgoingDataThread(incoming_queue=q1, outgoing_queue=q2, name='consumer')

    p.start()
    time.sleep(2)
    c.start()
    time.sleep(2)
