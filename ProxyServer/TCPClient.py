from scapy.all import *
import logging


class TCPClient(threading.Thread):
    def __init__(self, remote_host, remote_port, in_queue, out_queue, stop_event):
        super(TCPClient, self).__init__()
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.logger = logging.getLogger("tcp client")
        self.stop_event = stop_event

    def run(self):
        # TODO: add error handling
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((self.remote_host, self.remote_port))
        while True:
            s = threading.Thread(target=self.send_to_server, args=(self.in_queue, remote_socket,))
            r = threading.Thread(target=self.get_response_from_destination, args=(remote_socket,
                                                                                  self.out_queue))
            s.start()
            r.start()
        print "[+] Releasing resources..."
        remote_socket.shutdown(socket.SHUT_RDWR)
        remote_socket.close()

    @staticmethod
    def get_response_from_destination(src, out_queue):
        while True:
            tcp_response = src.recv(0x400)
            if len(tcp_response) == 0:
                print "[-] No data received! Breaking..."
                # TODO: add indicative exceptionS
                raise Exception('TCP Exception')
            out_queue.put(tcp_response)
        src.shutdown(socket.SHUT_RDWR)
        src.close()

    @staticmethod
    def send_to_server(in_queue, dst):
        while True:
            if not in_queue.empty():
                try:
                    tcp_data = in_queue.get()
                    if len(tcp_data) == 0:
                        print "[-] No data received! Breaking..."
                        continue
                    dst.send(tcp_data)
                except Exception as ex:
                    logging.warning("{0}".format(ex.message))
                    traceback.print_exc()
                    break
        dst.shutdown(socket.SHUT_RDWR)
        dst.close()
