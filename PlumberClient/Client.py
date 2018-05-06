import sys
sys.path.append('../')
from scapy.all import *
from Protocol.PlumberPacket import PlumberPacket
from scapy.layers.inet import IP, ICMP, TCP, UDP
import threading
import time
import logging
import Queue
import struct

logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )

BUF_SIZE = 100
in_tcp_queue = Queue.Queue(BUF_SIZE)
out_icmp_queue = Queue.Queue(BUF_SIZE)


def get_plumberpacket(base_proto, magic, pkt):
    if base_proto in pkt and Raw in pkt:
        logging.debug("base_proto={protocol}, magic={_magic}".format(protocol=base_proto, _magic=magic))
        plum_packet = PlumberPacket(pkt[base_proto][Raw].load)
        if plum_packet.magic == magic:
            return plum_packet
    return None


def generate_plumberpacket(base_proto, magic, pkt):
    payload = pkt[base_proto]
    dst_ip = pkt[IP].dst

    return PlumberPacket(magic=magic, message_target="server", message_type="data", ip=dst_ip, data=payload)


def generate_icmp_wrapper(proxy_addr, plumber_pkt):
    ip_layer = IP(dst=proxy_addr)
    icmp_layer = ICMP(type="echo-request")

    return ip_layer / icmp_layer / plumber_pkt


class IncomingDataThread(threading.Thread):
    def __init__(self, incoming_queue, packet_filter, protocol=TCP, target=None, name=None):
        super(IncomingDataThread, self).__init__()
        self.target = target
        self.name = name
        self.packet_filter_func = packet_filter
        self.protocol = protocol
        self.counter = 0
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
            logging.debug("Client packet " + pkt.show(dump=True))
            self.queue.put(pkt)

        return custom_action


class OutgoingDataThread(threading.Thread):
    def __init__(self, incoming_queue, outgoing_queue, protocol=ICMP, target=None, name=None):
        super(OutgoingDataThread, self).__init__()
        self.target = target
        self.name = name
        self.counter = 0
        self.protocol = protocol
        self.in_queue = incoming_queue
        self.out_queue = outgoing_queue
        return

    def run(self):
        while True:
            if not self.in_queue.empty():
                orig_pkt = self.in_queue.get()
                logging.info("got packet")
                logging.debug(orig_pkt.show(dump=True))
                if IP in orig_pkt:
                    plumer_pkt = generate_plumberpacket(self.protocol, self.magic, orig_pkt)
                    if TCP in orig_pkt or UDP in orig_pkt:
                        out_pkt = generate_icmp_wrapper(self.target, plumer_pkt)
                    else:
                        continue
                    send(out_pkt)
                self.counter += 1
                time.sleep(0.001)
        return


if __name__ == '__main__':
    p = IncomingDataThread(incoming_queue=in_tcp_queue, name='tcp interpreter', protocol=TCP,
                           packet_filter=lambda x: (x.haslayer(IP) and x.haslayer(TCP) and
                                                    x.getlayer(TCP).dport == 8888))

    c = OutgoingDataThread(incoming_queue=in_tcp_queue, outgoing_queue=out_icmp_queue, name='consumer',
                           target="188.166.148.53")

    p.start()
    time.sleep(2)
    c.start()
    time.sleep(2)
