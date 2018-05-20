import sys
sys.path.append('../')
from Protocol import *
from scapy.all import *
import logging


def plumberpacket_data_res(tcp_data, old_plum_pkt):
    plumber_pkt = DataPacket()
    plumber_pkt.message_target = "client"
    plumber_pkt.magic = old_plum_pkt.magic
    plumber_pkt.message_type = old_plum_pkt.message_type
    plumber_pkt.ip, plumber_pkt.src_ip = old_plum_pkt.ip, old_plum_pkt.src_ip
    plumber_pkt.id, plumber_pkt.seq = old_plum_pkt.id, old_plum_pkt.seq
    return plumber_pkt / tcp_data


class TCPClient(threading.Thread):
    def __init__(self, socks_host, socks_port, in_queue, out_queue, stop_event,
                 magic=12345):
        super(TCPClient, self).__init__()
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.logger = logging.getLogger("tcp client")
        self.stop_event = stop_event
        self.magic = magic

    def run(self):
        # TODO: add error handling
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((self.socks_host, self.socks_port))
        remote_socket.settimeout(5)

        s = threading.Thread(target=self.send_to_server, args=(self.in_queue, self.out_queue,
                                                               remote_socket,))
        s.start()

        s.join()

        remote_socket.shutdown(socket.SHUT_RDWR)
        remote_socket.close()

    def send_to_server(self, in_queue, out_queue, socks_socket):
        while True:
            # TODO: add conn alive func
            if not in_queue.empty():
                try:
                    tcp_data = in_queue.get()
                    if isinstance(tcp_data, PlumberPacket) and tcp_data.message_type == 2:
                        self.logger.debug("got data plum packet to send over socks:\n{}".format(tcp_data))
                        socks_socket.sendall(bytes(tcp_data[Raw]))
                        # spawn new thread for receive data
                        # get_data_thread = threading.Thread(target=self.get_data,
                        #                                    args=(tcp_data, self.out_queue, socks_socket,))
                        # get_data_thread.start()

                        tcp_res = socks_socket.recv(0x400)
                        out_queue.put(plumberpacket_data_res(tcp_res, tcp_data))
                        while tcp_res:
                            tcp_res = socks_socket.recv(0x400)
                            out_queue.put(plumberpacket_data_res(tcp_res, tcp_data))
                except Exception as ex:
                    logging.warning("{0}".format(ex.message))
                    traceback.print_exc()
                    break

    def get_data(self, old_pkt, out_queue, socks_socket):
        while not self.stop_event.is_set():
            try:
                tcp_res = socks_socket.recv(0x400)
                out_queue.put(plumberpacket_data_res(tcp_res, old_pkt))
            except socket.timeout:
                break
            except:
                break
