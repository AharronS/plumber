import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from OutgoingCovertThread import OutgoingCovertThread
from TCPServer import TCPServer
import threading
from SocksClient import Client
import secretsocks
import SocketServer
from TCPServer_socket import IncomingTCPSocketHandler


BUF_SIZE = 100
logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


def main():
    try:
        _stop_event = threading.Event()
        _stop_event.clear()
        server_addr = '188.166.148.53'
        in_queue = Queue.Queue(BUF_SIZE)
        out_queue = Queue.Queue(BUF_SIZE)
        HOST, PORT = "localhost", 12347
        server = IncomingTCPSocketHandler(in_queue, out_queue, _stop_event, HOST, PORT)
        w = OutgoingCovertThread(name='outgoing covert', out_queue=out_queue,
                                 in_queue=in_queue, stop_event=_stop_event, magic=12345,
                                 server_ip=server_addr)

        threads = [server,
                   w]
        for thread in threads:
            thread.start()
            time.sleep(2)

        for thread in threads:
            thread.join()
    except Exception:
        _stop_event.set()
        sys.exit()


if __name__ == '__main__':
    main()
