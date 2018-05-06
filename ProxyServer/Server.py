import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from IncomingCovertThread import IncomingCovertDataThread
from OutgoingDataThread import OutgoingDataThread
from OutgoingCovertThread import OutgoingCovertThread
import threading


BUF_SIZE = 100
logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


def main():
    _stop_event = threading.Event()
    _stop_event.clear()

    q1 = Queue.Queue(BUF_SIZE)
    q2 = Queue.Queue(BUF_SIZE)
    p = IncomingCovertDataThread(name='icmp interpreter', stop_event=_stop_event,
                                 incoming_queue=q1,
                                 packet_filter=lambda x: (x.haslayer(IP) and x.haslayer(ICMP) and
                                                          x.getlayer(ICMP).type == 8))
    c = OutgoingDataThread(name='outgoing sender', stop_event=_stop_event,
                           incoming_queue=q1, outgoing_queue=q2)
    w = OutgoingCovertThread(name='outgoing covert', stop_event=_stop_event,
                             incoming_queue=q2)

    threads = [p, c, w]
    for thread in threads:
        thread.start()
        time.sleep(2)

    for thread in threads:
        thread.join()


if __name__ == '__main__':
    main()
