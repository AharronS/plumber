import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from IncomingDataThread import IncomingDataThread
from OutgoingCovertThread import OutgoingCovertThread
from TCPServer import TCPServer
import threading


BUF_SIZE = 100
logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


def main():
    _stop_event = threading.Event()
    _stop_event.clear()
    listen_port = 51234
    in_queue = Queue.Queue(BUF_SIZE)
    out_queue = Queue.Queue(BUF_SIZE)
    # p = IncomingDataThread(name='TCP interpreter', stop_event=_stop_event,
    #                        out_queue=out_queue,
    #                        packet_filter=lambda x: (x.haslayer(IP) and x.haslayer(TCP) and
    #                                                       x.getlayer(TCP).dport == listen_port))

    # local_host, local_port, max_connection, in_queue, stop_event
    c = TCPServer(local_host="127.0.0.1", local_port=listen_port, max_connection=1,
                  stop_event=_stop_event, in_queue=in_queue, out_queue=out_queue)
    # out_queue, in_queue, stop_event, magic, server_ip, name
    w = OutgoingCovertThread(name='outgoing covert', out_queue=out_queue,
                             in_queue=in_queue, stop_event=_stop_event, magic=12345,
                             server_ip="127.0.0.1")

    # threads = [p, c, w]
    threads = [c, w]
    for thread in threads:
        thread.start()
        time.sleep(2)

    for thread in threads:
        thread.join()


if __name__ == '__main__':
    main()
