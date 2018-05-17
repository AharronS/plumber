from scapy.all import *
import logging


class TCPServer(threading.Thread):
    def __init__(self, local_host, local_port, max_connection, in_queue, out_queue, stop_event):
        super(TCPServer, self).__init__()
        self.local_host = local_host
        self.local_port = local_port
        self.max_connection = max_connection
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.logger = logging.getLogger("incomming")
        self.stop_event = stop_event

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.local_host, self.local_port))
        server_socket.listen(self.max_connection)
        while True:
            local_socket, local_address = server_socket.accept()
            print "[+] Tunnel connected! Tranfering data..."
            s = threading.Thread(target=self.send_to_client, args=(self.in_queue, local_socket, ))
            r = threading.Thread(target=self.response_to_request, args=(local_socket,
                                                                        self.out_queue))
            s.start()
            r.start()
        print "[+] Releasing resources..."
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        print "[+] Closing server..."
        server_socket.shutdown(socket.SHUT_RDWR)
        server_socket.close()
        print "[+] Server shuted down!"

    @staticmethod
    def response_to_request(src, out_queue):
        while True:
            buffer = src.recv(0x400)
            if len(buffer) == 0:
                print "[-] No data received! Breaking..."
                # TODO: add indicative exceptionS
                raise Exception('TCP Exception')
            out_queue.put(buffer)
        src.shutdown(socket.SHUT_RDWR)
        src.close()

    @staticmethod
    def send_to_client(in_queue, dst):
        while True:
            if not in_queue.empty():
                try:
                    tcp_pkt = in_queue.get()
                    if len(tcp_pkt) == 0:
                        print "[-] No data received! Breaking..."
                        continue
                    dst.send(bytes(tcp_pkt))
                except Exception as ex:
                    logging.warning("{0}".format(ex.message))
                    traceback.print_exc()
                    break
        dst.shutdown(socket.SHUT_RDWR)
        dst.close()
