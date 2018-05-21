import sys
sys.path.append('../')
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
from PlumberDataTypes import *
from PlumberDataTypes.DataPacket import DataPacket
import threading
import logging
import traceback
import time
from random import randint


def generate_icmp_wrapper(plumber_pkt, dst_ip):
    ip_layer = IP(dst=dst_ip)
    icmp_layer = ICMP(type="echo-request", id=1337)
    return ip_layer / icmp_layer / plumber_pkt


def plumberpacket_wrapper(magic, tcp_data):
    plumber_pkt = DataPacket()
    plumber_pkt.message_target = "server"
    plumber_pkt.magic = magic
    return plumber_pkt / tcp_data


def generate_poll_packet(magic, dst_ip):
    plumber_pkt = PollPacket()
    plumber_pkt.message_target = "server"
    plumber_pkt.magic = magic
    return generate_icmp_wrapper(plumber_pkt, dst_ip)


def get_plumberpacket_packet(magic, pkt):
    if IP in pkt and ICMP in pkt and Raw in pkt:
        plum_packet = PlumberPacket(pkt[ICMP][Raw].load)
        if plum_packet.magic == magic:
            plum_packet.src_ip = pkt[IP].src
            plum_packet.id, plum_packet.seq = pkt[ICMP].id, pkt[ICMP].seq
            return plum_packet
        else:
            raise Exception("Not PlumberPacket!")


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
        poll_thread = threading.Thread(target=self.send_poll_requests, args=())
        #poll_thread.start()
        while not self.stop_event.is_set():
            if not self.out_queue.empty():
                try:
                    # get data from tcp socket queue
                    tcp_data = self.out_queue.get()
                    plum_pkt = plumberpacket_wrapper(self.magic, tcp_data)
                    icmp_pkt = generate_icmp_wrapper(plum_pkt, self.target)
                    self.logger.debug("send icmp: {}".format(icmp_pkt.summary()))
                    # TODO: Add loop for sending packet
                    covert_res = sr1(icmp_pkt, timeout=10)
                    if covert_res:
                        self.logger.debug("response icmp: {}".format(covert_res.show2(dump=True)))
                        try:
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
                    continue
        #poll_thread.join()

    def send_poll_requests(self):
        intervals = 5
        poll_pkt = generate_poll_packet(self.magic, self.target)
        while not self.stop_event.is_set():
            if self.out_queue.empty():
                covert_res = sr1(poll_pkt, timeout=10)
                if covert_res:
                    if covert_res:
                        self.logger.debug("response icmp: {}".format(covert_res.show2(dump=True)))
                        try:
                            plum_pkt = get_plumberpacket_packet(self.magic, covert_res)
                            if plum_pkt is not None:
                                self.in_queue.put(plum_pkt)
                                intervals = 0
                                self.counter += 1
                        except Exception:
                            self.logger.exception("Get poll packet failed")
                            continue
            time.sleep(intervals)
            intervals = 5
        return
