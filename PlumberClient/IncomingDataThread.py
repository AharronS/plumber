import sys
sys.path.append('../')
from scapy.all import *
from Protocol import *
from Protocol.DataPacket import DataPacket
from scapy.layers.inet import IP, ICMP, TCP, UDP
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


def plumberpacket_wrapper(base_proto, magic, pkt, dst_ip):
    plumber_pkt = DataPacket()
    plumber_pkt.message_target = "server"
    plumber_pkt.ip = ""
    payload = pkt[base_proto]
    return PlumberPacket(magic=magic, message_target="client", message_type="data",
                         ip=dst_ip, data=payload)


def stop_sniff(pkt):
    if ICMP in pkt and pkt[ICMP].id == 11111 and pkt[ICMP].seq == 11111:
        logging.debug("stop filter!\n" + pkt.summary())
        return True
    else:
        return False


class IncomingCovertDataThread(threading.Thread):
    def __init__(self, incoming_queue, packet_filter, stop_event, protocol=TCP, magic=12345,
                 target=None, name=None):
        super(IncomingCovertDataThread, self).__init__()
        self.target = target
        self.name = name
        self.packet_filter_func = packet_filter
        self.protocol = protocol
        self.counter = 0
        self.magic = magic
        self.queue = incoming_queue
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
                self.logger.debug("{0} packet! {1}".format(str(self.protocol), pkt.summary()))
                if TCP in pkt or UDP in pkt:
                    try:
                        plum_pkt = get_plumberpacket_packet(self.protocol, self.magic, pkt)
                    except Exception as ex:
                        self.logger.info("unknown packet")
                        return custom_action
                    if plum_pkt:
                        self.logger.info("incoming PlumberPacket!")
                        self.queue.put(plum_pkt)
                    else:
                        self.logger.debug("not plumber packet")
            else:
                self.logger.debug("unknown protocol: \n" + pkt.show(dump=True))
            self.counter += 1
        return custom_action
