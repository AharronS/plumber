from scapy.all import *
from IncomingPlumber import IncomingPlumberDataThread
from OutgoingData import OutgoingDataThread
from OutgoingPlumberData import OutgoingPlumberThread
from scapy.layers.inet import IP, ICMP, TCP
import logging
import Queue
from Modules import *

logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )

BUF_SIZE = 100
q1 = Queue.Queue(BUF_SIZE)
q2 = Queue.Queue(BUF_SIZE)

if __name__ == '__main__':
    p = IncomingPlumberDataThread(incoming_queue=q1, name='icmp interpreter', packet_filter=lambda x: (x.haslayer(IP) and
                                                                                                       x.haslayer(ICMP) and
                                                                                                       x.getlayer(ICMP).type == 8))

    c = OutgoingDataThread(incoming_queue=q1, protocol=TCP, outgoing_queue=q2, name='send raw data')

    o = OutgoingPlumberThread(incoming_queue=q2, name='response plumber packet')
    p.start()
    time.sleep(0.2)
    c.start()
    time.sleep(0.2)
    o.start()



"""
>>> sys.path.append("/home/zen/git/plumber/Protocol")
>>> import PlumberPacket
>>> PlumberPacket
"""