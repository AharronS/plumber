import sys
sys.path.append('../')
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from PlumberDataTypes import *
from PlumberDataTypes.DataPacket import DataPacket
import threading
import logging
import traceback


"""
generate icmp wrapper for plumber packets
"""


def generate_icmp_wrapper(plumber_pkt, dst_ip):
    ip_layer = IP(dst=dst_ip)
    icmp_layer = ICMP(type="echo-request", id=1337)
    return ip_layer / icmp_layer / plumber_pkt


"""
wrap data with plumber packet(our tunnelling protocol)
"""


def plumberpacket_wrapper(magic, tcp_data):
    plumber_pkt = DataPacket()
    plumber_pkt.message_target = "server"
    plumber_pkt.magic = magic
    return plumber_pkt / tcp_data


"""
generate poll request to server with PollPacket(PlumberDataTypes package)
"""


def generate_poll_packet(magic, dst_ip):
    plumber_pkt = PollPacket()
    plumber_pkt.message_target = "server"
    plumber_pkt.magic = magic
    return generate_icmp_wrapper(plumber_pkt, dst_ip)


"""
extracting plumber packet from ICMP packet.
The function checks whether the magic is correct, if not the function throws an exception
"""


def get_plumberpacket_packet(magic, pkt):
    if IP in pkt and ICMP in pkt and Raw in pkt:
        plum_packet = PlumberPacket(pkt[ICMP][Raw].load)
        if plum_packet.magic == magic:
            plum_packet.src_ip = pkt[IP].src
            plum_packet.id, plum_packet.seq = pkt[ICMP].id, pkt[ICMP].seq
            return plum_packet
        else:
            raise Exception("Not PlumberPacket!")


"""
Outgoing thread - 
The role of the thread is to manage all the covert channel being performed to the proxy server
"""


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

    def stop(self):
        self.stop_event.set()

    def stopped(self):
        return self.stop_event.is_set()

    def run(self):
        poll_pkt = generate_poll_packet(self.magic, self.target)
        while not self.stop_event.is_set():
            # if out_queue not empty, get data from the queue and send data over icmp
            if not self.out_queue.empty():
                try:
                    # get data from tcp socket queue
                    tcp_data = self.out_queue.get()
                    plum_pkt = plumberpacket_wrapper(self.magic, tcp_data)
                    # wrap data with icmp
                    icmp_pkt = generate_icmp_wrapper(plum_pkt, self.target)
                    self.logger.debug("send icmp: {}".format(icmp_pkt.summary()))
                    # get covert response
                    covert_res = sr1(icmp_pkt, timeout=10)
                    if covert_res:
                        self.logger.debug("response icmp: {}".format(covert_res.show2(dump=True)))
                        try:
                            # if the extraction succeed put packet on in_queue
                            plum_pkt = get_plumberpacket_packet(self.magic, covert_res)
                            if plum_pkt is not None:
                                self.in_queue.put(plum_pkt)
                                self.counter += 1
                        except Exception:
                            self.logger.exception("Get plumber packet failed")
                            continue
                except Exception as ex:
                    self.logger.warning("{0}".format(ex.message))
                    traceback.print_exc()
            else:
                # if out_queue empty, send poll request to server
                # for more information about polling process go to the documentation file
                if not self.stop_event.is_set():
                    # try to get data from the server
                    covert_res = sr1(poll_pkt, timeout=10)
                    if covert_res:
                        # if there is data, try to extract plumber protocol from packet
                        self.logger.debug("response icmp: {}".format(covert_res.show2(dump=True)))
                        try:
                            plum_pkt = get_plumberpacket_packet(self.magic, covert_res)
                            if plum_pkt is not None:
                                self.in_queue.put(plum_pkt)
                                self.counter += 1
                        except Exception:
                            self.logger.exception("Get poll packet failed")
                            continue
