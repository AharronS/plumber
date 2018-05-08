import secretsocks
import socket
import Queue


# The client class which connects out to a server over TCP/IP
class Client(secretsocks.Client):
    # Initialize our data channel
    def __init__(self, ip, port):
        secretsocks.Client.__init__(self)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.settimeout(2)
        self.data_channel = s
        self.alive = True
        self.start()

    # Receive data from our data channel and push it to the receive queue
    def recv(self):
        while self.alive:
            try:
                data = self.data_channel.recv(4092)
                self.recvbuf.put(data)
            except socket.timeout:
                continue
            except:
                self.alive = False
                self.data_channel.close()

    # Take data from the write queue and send it over our data channel
    def write(self):
        while self.alive:
            try:
                data = self.writebuf.get(timeout=10)
            except Queue.Empty:
                continue
            self.data_channel.sendall(data)


