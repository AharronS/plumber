import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from IncomingCovertThread import IncomingCovertDataThread
from OutgoingCovertThread import OutgoingCovertThread
from TCPClient import TCPClient
import threading
import subprocess
from OutgoingDict import OutgoingDict
from ClientsDict import ClientsDict


BUF_SIZE = 1000
logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )

#
# def start_Socks_server(stop_event, in_queue, out_queue):
#     Server(stop_event, in_queue, out_queue)


def main():
    _stop_event = threading.Event()
    _stop_event.clear()
    in_queue = Queue.Queue(BUF_SIZE)
    out_dict = OutgoingDict()
    clients_dict = ClientsDict()
    poll_queue = Queue.Queue(BUF_SIZE)

    p = subprocess.Popen(['/usr/bin/python3', '/root/SocksServer.py'])
    print "Starting soscks Sever : " + str(p.pid)

    p = IncomingCovertDataThread(name='icmp interpreter', stop_event=_stop_event,
                                 incoming_queue=in_queue, poll_queue=poll_queue,
                                 clients_dict=clients_dict, out_dict=out_dict,
                                 packet_filter=lambda x: (x.haslayer(IP) and x.haslayer(ICMP) and
                                                          x.getlayer(ICMP).type == 8))
    c = TCPClient("0.0.0.0", 9011, in_queue, out_dict, _stop_event, magic=12345)

    w = OutgoingCovertThread(name='outgoing covert', stop_event=_stop_event,
                             out_dict=out_dict, clients_dict=clients_dict)

    threads = [p, c, w]
    for thread in threads:
        thread.start()
        time.sleep(2)

    for thread in threads:
        thread.join()


if __name__ == '__main__':
    main()
