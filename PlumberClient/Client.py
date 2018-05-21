import sys
sys.path.append('../')
import logging
import Queue
from scapy.layers.inet import *
from OutgoingCovertThread import OutgoingCovertThread
import threading
from TCPServer_socket import IncomingTCPSocketHandler
from TCPServer_SocketServer import SimpleServer, SimpleRequestHandler

BUF_SIZE = 1000
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
        """
        server = SimpleServer(('', 12347), SimpleRequestHandler, in_queue, out_queue, _stop_event)
        """

        w = OutgoingCovertThread(name='outgoing covert', out_queue=out_queue,
                                 in_queue=in_queue, stop_event=_stop_event, magic=12345,
                                 server_ip=server_addr)
        """
        t = threading.Thread(target=server.serve_forever)
        t.setDaemon(True)  # don't hang on exit
        """

        threads = [server, w]
        for thread in threads:
            thread.start()
            time.sleep(2)

        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        _stop_event.set()
        sys.exit(0)

    except Exception as ex:
        logging.exception("Error")
        _stop_event.set()
        sys.exit(0)


if __name__ == '__main__':
    main()
