import sys
sys.path.append('../')
import PlumberDataTypes
import logging
import Queue
from scapy.layers.inet import *
from IncomingCovertThread import IncomingCovertDataThread
from OutgoingCovertThread import OutgoingCovertThread
from TCPClient import TCPClient
import threading
from OutgoingDict import OutgoingDict
from ClientsDict import ClientsDict
from SocksServer import SocksServer
import signal

user_home = os.path.expanduser('~')
pid_file = user_home + '/.pysocks.pid'
BUF_SIZE = 1000


def signal_handler(signal_hand, frame):
    SocksServer.stop(pid_file)
    os.kill(os.getgid(), signal.SIGTERM)
    sys.exit(0)


def start_server(listen_host, listen_port, users, passwords):
    try:
        signal.signal(signal.SIGINT, signal_handler)
        stop_event = threading.Event()
        in_queue = Queue.Queue(BUF_SIZE)
        out_dict = OutgoingDict()
        clients_dict = ClientsDict()
        poll_queue = Queue.Queue(BUF_SIZE)
        logging.info("starting socks server..")
        socks_thread = threading.Thread(target=SocksServer.start_socks_server, args=(listen_port,
                                                                                     users, passwords, None,))
        socks_thread.daemon = True
        socks_thread.start()
        time.sleep(5)
        logging.info("starting incoming icmp channel..")
        incoming_thread = IncomingCovertDataThread(stop_event=stop_event,
                                                   incoming_queue=in_queue, poll_queue=poll_queue,
                                                   clients_dict=clients_dict, out_dict=out_dict,
                                                   packet_filter=lambda x: (x.haslayer(IP) and x.haslayer(ICMP) and
                                                                            x.getlayer(ICMP).type == 8))
        tcp_client_thread = TCPClient(listen_host, listen_port, in_queue, out_dict, stop_event, magic=12345)
        logging.info("starting outgoing icmp channel..")
        outgoing_thread = OutgoingCovertThread(stop_event=stop_event,
                                               out_dict=out_dict, clients_dict=clients_dict)

        threads = [incoming_thread, tcp_client_thread, outgoing_thread]
        for thread in threads:
            thread.start()
            time.sleep(2)


        for thread in threads:
            thread.join()

        logging.info("exiting server..")
        SocksServer.stop(pid_file)
    except Exception:
        logging.exception("error while server logic")
        SocksServer.stop(pid_file)
        os.kill(os.getgid(), signal.SIGTERM)
        sys.exit(0)


if __name__ == '__main__':
    start_server(listen_host="0.0.0.0", listen_port=9011, users="username", passwords="password")
