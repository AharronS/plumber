from PlumberClient import secretsocks
import Queue


# The client class which connects out to a server over TCP/IP
class Client(secretsocks.Client):
    # Initialize our data channel
    def __init__(self, out_queue, in_queue, stop_event):
        secretsocks.Client.__init__(self)
        self.out_queue = out_queue
        self.in_queue = in_queue
        self.stop_event = stop_event
        self.alive = True
        self.start()

    # Receive data from our data channel and push it to the receive queue
    def recv(self):
        while not self.stop_event.is_set():
            try:
                data = self.in_queue.get(timeout=10)
                self.recvbuf.put(data)
            except Queue.Empty:
                continue

    # Take data from the write queue and send it over our data channel
    def write(self):
        while not self.stop_event.is_set():
            try:
                data = self.writebuf.get(timeout=10)
            except Queue.Empty:
                continue
            self.out_queue.put(data)
