import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from IncomingCovertThread import IncomingCovertDataThread
from OutgoingDataThread import OutgoingDataThread
from OutgoingCovertThread import OutgoingCovertThread
from TCPClient import TCPClient
import threading


BUF_SIZE = 100
logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


def main():
    _stop_event = threading.Event()
    _stop_event.clear()

    in_queue = Queue.Queue(BUF_SIZE)
    out_queue = Queue.Queue(BUF_SIZE)
    p = IncomingCovertDataThread(name='icmp interpreter', stop_event=_stop_event,
                                 incoming_queue=in_queue,
                                 packet_filter=lambda x: (x.haslayer(IP) and x.haslayer(ICMP) and
                                                          x.getlayer(ICMP).type == 8))
    # c = OutgoingDataThread(name='outgoing sender', stop_event=_stop_event,
    #                        incoming_queue=q1, outgoing_queue=q2)
    c = TCPClient("www.example.com", 80, in_queue, out_queue, _stop_event)
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
