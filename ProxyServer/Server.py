import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from IncomingCovertThread import IncomingCovertDataThread
from OutgoingDataThread import OutgoingDataThread
from OutgoingCovertThread import OutgoingCovertThread


logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


if __name__ == '__main__':
    BUF_SIZE = 100
    q1 = Queue.Queue(BUF_SIZE)
    q2 = Queue.Queue(BUF_SIZE)

    p = IncomingCovertDataThread(name='icmp interpreter', incoming_queue=q1,  packet_filter=lambda x: (x.haslayer(IP) and
                                                                             x.haslayer(ICMP) and
                                                                             x.getlayer(ICMP).type == 8))

    c = OutgoingDataThread(name='outgoing sender', incoming_queue=q1, outgoing_queue=q2)

    w = OutgoingCovertThread(name='outgoing covert', incoming_queue=q2)


    p.start()
    time.sleep(2)
    c.start()
    time.sleep(2)
