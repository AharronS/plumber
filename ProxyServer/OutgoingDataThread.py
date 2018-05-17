import sys
sys.path.append('../')
from scapy.all import *
from Protocol import *
from scapy.layers.inet import IP, TCP
import threading
import logging
import copy


def generate_plumberpacket(base_proto, magic, pkt, dst_ip):
    payload = pkt[base_proto]
    return PlumberPacket(magic=magic, message_target="client", message_type="data",
                         ip=dst_ip, data=payload)


class OutgoingDataThread(threading.Thread):
    def __init__(self, incoming_queue, outgoing_queue, stop_event, magic=12345, protocol=TCP, target=None, name=None):
        super(OutgoingDataThread, self).__init__()
        self.target = target
        self.name = name
        self.counter = 0
        self.protocol = protocol
        self.in_queue = incoming_queue
        self.out_queue = outgoing_queue
        self.logger = logging.getLogger("outgoing")
        self.magic = magic
        self.stop_event = stop_event

    def run(self):
        while not self.stop_event.is_set():
            if not self.in_queue.empty():
                plumber_item = self.in_queue.get()
                self.logger.debug(plumber_item[PlumberPacket].show(dump=True))
                if plumber_item[PlumberPacket].message_type == 2:
                    self.logger.info("got Data PlumberPacket!")
                    data = self.protocol(plumber_item[PlumberPacket].data)
                    if hasattr(data, 'chksum'):
                        del data.chksum

                    # data_to_send = IP(dst=plumber_item.ip)/data
                    # TODO: remove this line
                    del data.sport
                    data.dport = 80
                    data_to_send = IP(dst="example.com")/data

                    self.logger.debug("sending:\n{0}".format(data_to_send.summary()))
                    response = sr1(data_to_send, timeout=2)
                    self.logger.debug("recieve:\n{0}".format(response.summary()))

                    res_plumber = copy.deepcopy(plumber_item)
                    res_plumber.ip, res_plumber.src_ip = res_plumber.src_ip, response[IP].dst
                    res_plumber.data = self.protocol(response.getlayer(self.protocol))
                    self.out_queue.put(res_plumber)
                self.counter += 1
                time.sleep(0.001)
        return
