import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from OutgoingCovertThread import OutgoingCovertThread
import threading
from TCPServerForwarder import IncomingTCPSocketHandler

#TODO - remove this afterwards
logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s', )


def start_client(listen_host, listen_port, proxy_addr, buff_size=1000):
    try:
        stop_event = threading.Event()
        in_queue = Queue.Queue(buff_size)
        out_queue = Queue.Queue(buff_size)

        server_thread = IncomingTCPSocketHandler(in_queue, out_queue, stop_event, listen_host,
                                                 listen_port)
        outgoing_thread = OutgoingCovertThread(name='outgoing covert', out_queue=out_queue,
                                 in_queue=in_queue, stop_event=stop_event, magic=12345,
                                 server_ip=proxy_addr)

        threads = [server_thread, outgoing_thread]
        for thread in threads:
            thread.start()
            time.sleep(2)

        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        logging.exception("KeyboardInterrupt")
        stop_event.set()
        sys.exit(0)

    except Exception as ex:
        logging.exception("Error")
        stop_event.set()
        sys.exit(0)


if __name__ == '__main__':
    start_client(listen_host="localhost", listen_port=12347, proxy_addr="188.166.148.53")
