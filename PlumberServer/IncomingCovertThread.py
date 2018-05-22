import sys
sys.path.append('../')
from scapy.all import *
from PlumberDataTypes import *
from scapy.layers.inet import IP, ICMP
import threading
import logging
import os, signal

"""
extract Plumber Packet data from ICMP packet
"""


def get_plumberpacket_packet(magic, pkt):
    if IP in pkt and ICMP in pkt and Raw in pkt:
        plum_packet = PlumberPacket(pkt[ICMP][Raw].load)
        if plum_packet.magic == magic:
            # assign the source ip to the plumber packet for tracking
            # in next stages of process
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


"""
IncomingCovertDataThread - 
The role of this thread is to manage all the covert data from clients. 
"""


class IncomingCovertDataThread(threading.Thread):
    def __init__(self, incoming_queue, poll_queue, packet_filter, stop_event, clients_dict,
                 out_dict, protocol=ICMP, magic=12345,
                 target=None):
        super(IncomingCovertDataThread, self).__init__()
        self.target = target
        self.name = "incoming ICMP"
        self.packet_filter_func = packet_filter
        self.protocol = protocol
        self.counter = 0
        self.magic = magic
        self.in_queue = incoming_queue
        self.out_dict = out_dict
        self.poll_queue = poll_queue
        self.logger = logging.getLogger(self.name)
        self.stop_event = stop_event
        self.clients_dict = clients_dict

    def run(self):
        self.logger.info("Starting " + self.name)
        # sniff icmp packets and dissect the packets
        sniff(lfilter=self.packet_filter_func, prn=self.dissect_packet(), stop_filter=stop_sniff)
        self.stop_event.set()
        self.logger.info("Exiting " + self.name)
        return

    def dissect_packet(self):
        def custom_action(pkt):
            if self.protocol in pkt:
                self.logger.debug("incoming packet:\n{}".format(pkt.summary()))
                if Raw in pkt:
                    try:
                        # try to extract data from packets
                        plum_pkt = get_plumberpacket_packet(self.magic, pkt)
                        self.logger.info("incoming PlumberPacket!")
                        # if it data packet
                        if plum_pkt.message_type == 2:
                            # increment the counter ot this client
                            self.clients_dict.incoming_packet(plum_pkt)
                            # put packet on in_queue
                            self.in_queue.put(plum_pkt)
                        # if it poll packets
                        elif plum_pkt.message_type == 5:
                            if self.out_dict.is_client_exist(plum_pkt.src_ip):
                                self.clients_dict.incoming_packet(plum_pkt)
                            self.logger.debug("incoming poll request from {}".format(
                                plum_pkt.src_ip))
                    except Exception as ex:
                        self.logger.exception("unknown packet")
                        return custom_action
            else:
                self.logger.debug("unknown protocol: \n" + pkt.show(dump=True))
            self.counter += 1
        return custom_action
