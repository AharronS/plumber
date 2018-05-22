import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from IncomingCovertThread import IncomingCovertDataThread
from OutgoingCovertThread import OutgoingCovertThread
from TCPClient import TCPClient
import threading
from OutgoingDict import OutgoingDict
from ClientsDict import ClientsDict

BUF_SIZE = 1000
logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


def start_server(listen_host, listen_port, username, password, socks_port=9191):
    stop_event = threading.Event()
    in_queue = Queue.Queue(BUF_SIZE)
    out_dict = OutgoingDict()
    clients_dict = ClientsDict()
    poll_queue = Queue.Queue(BUF_SIZE)

    incoming_thread = IncomingCovertDataThread(stop_event=stop_event,
                                               incoming_queue=in_queue, poll_queue=poll_queue,
                                               clients_dict=clients_dict, out_dict=out_dict,
                                               packet_filter=lambda x: (x.haslayer(IP) and x.haslayer(ICMP) and
                                                                        x.getlayer(ICMP).type == 8))
    tcp_client_thread = TCPClient(listen_host, listen_port, in_queue, out_dict, stop_event, magic=12345)

    outgoing_thread = OutgoingCovertThread(stop_event=stop_event,
                                           out_dict=out_dict, clients_dict=clients_dict)

    threads = [incoming_thread, tcp_client_thread, outgoing_thread]
    for thread in threads:
        thread.start()
        time.sleep(2)

    for thread in threads:
        thread.join()


if __name__ == '__main__':
    start_server(listen_host="0.0.0.0", listen_port=9011, username="username", password="password")
