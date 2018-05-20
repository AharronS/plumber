import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from IncomingCovertThread import IncomingCovertDataThread
from OutgoingCovertThread import OutgoingCovertThread
from TCPClient import TCPClient
import threading
import secretsocks
from SocksServer import Server


BUF_SIZE = 100
logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )

#
# def start_Socks_server(stop_event, in_queue, out_queue):
#     Server(stop_event, in_queue, out_queue)


def main():
    _stop_event = threading.Event()
    _stop_event.clear()
    secretsocks.set_debug(True)
    in_queue = Queue.Queue(BUF_SIZE)
    out_queue = Queue.Queue(BUF_SIZE)

    p = IncomingCovertDataThread(name='icmp interpreter', stop_event=_stop_event,
                                 incoming_queue=in_queue,
                                 packet_filter=lambda x: (x.haslayer(IP) and x.haslayer(ICMP) and
                                                          x.getlayer(ICMP).type == 8))
    c = TCPClient("0.0.0.0", 9011, in_queue, out_queue, _stop_event, magic=12345)

    w = OutgoingCovertThread(name='outgoing covert', stop_event=_stop_event,
                             incoming_queue=out_queue)

    threads = [p, c, w]
    for thread in threads:
        thread.start()
        time.sleep(2)

    for thread in threads:
        thread.join()


if __name__ == '__main__':
    main()
