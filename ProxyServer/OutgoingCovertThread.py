import sys
sys.path.append('../')
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import threading
import logging
from OutgoingDict import ClientNotFoundInDict

def generate_icmp_wrapper(plumber_pkt):
    ip_layer = IP(dst=plumber_pkt.src_ip)
    icmp_layer = ICMP(type="echo-reply")
    icmp_layer.id = plumber_pkt.id
    icmp_layer.seq = plumber_pkt.seq
    return ip_layer / icmp_layer / plumber_pkt


class OutgoingCovertThread(threading.Thread):
    def __init__(self, out_dict, clients_dict, stop_event, protocol=TCP, target=None, name=None,
                 magic=12345):
        super(OutgoingCovertThread, self).__init__()
        self.target = target
        self.name = name
        self.counter = 0
        self.protocol = protocol
        self.out_dict = out_dict
        self.clients_dict = clients_dict
        self.logger = logging.getLogger("Covert response")
        self.magic = magic
        self.stop_event = stop_event

    def run(self):
        while not self.stop_event.is_set():
            if not self.out_dict.is_out_dict_empty():
                try:
                    try:
                        client_wait_key = self.clients_dict.get_waiting_client(self.out_dict.get_all_outgoing_keys())
                    except Exception as ex:
                        #TODO: fix it
                        continue
                    res_pkt = self.out_dict.get_plumber_pkt_from_dict_by_key(client_wait_key)
                    logging.info("got packet, {}".format(res_pkt.summary()))
                    if res_pkt:
                        out_pkt = generate_icmp_wrapper(res_pkt)
                    else:
                        self.logger.warning("weird packet" + res_pkt.show(dump=True))
                        continue
                    self.logger.debug("sending plumber packet response to client:{0}".format(
                        out_pkt.show2(dump=True)
                    ))
                    send(out_pkt)
                    self.clients_dict.outgoing_packet(out_pkt)
                    self.counter += 1
                except Exception:
                    self.logger.exception("get data from out_dict faileds")
                    continue
        return
