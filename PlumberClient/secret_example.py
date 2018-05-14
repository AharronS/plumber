from Server import Server
from OutgoingCovertThread import OutgoingCovertThread
from Client import Client
import secretsocks
import threading
import Queue


def start_fake_remote():
    Server('127.0.0.1', 8080)


if __name__ == '__main__':
    BUF_SIZE = 1000
    dst_addr = "188.166.148.53"
    #dst_addr = "127.0.0.1"
    _stop_event = threading.Event()
    _stop_event.clear()
    out_queue = Queue.Queue(BUF_SIZE)
    in_queue = Queue.Queue(BUF_SIZE)

    c = OutgoingCovertThread(out_queue, in_queue, _stop_event, 12345, dst_addr, name='CovertICMPSender')
    c.start()

    ##########
    # Set secretsocks into debug mode
    secretsocks.set_debug(True)

    # Create the client object
    print('Creating a the client...')
    client = Client(out_queue, in_queue, _stop_event)

    # Start the standard listener with our client
    print('Starting socks server...')
    listener = secretsocks.Listener(client, host='127.0.0.1', port=1080)
    listener.wait()