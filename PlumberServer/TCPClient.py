import sys
sys.path.append('../')
from PlumberDataTypes import *
from scapy.all import *
import logging
from OutgoingCovertThread import OutgoingCovertThread
import threading

def plumberpacket_data_res(tcp_data, old_plum_pkt):
    plumber_pkt = DataPacket()
    plumber_pkt.message_target = "client"
    plumber_pkt.magic = old_plum_pkt.magic
    plumber_pkt.message_type = old_plum_pkt.message_type
    plumber_pkt.ip, plumber_pkt.src_ip = old_plum_pkt.ip, old_plum_pkt.src_ip
    plumber_pkt.id, plumber_pkt.seq = old_plum_pkt.id, old_plum_pkt.seq
    return plumber_pkt / tcp_data


class TCPClient(threading.Thread):
    def __init__(self, socks_host, socks_port, in_queue, out_dict, stop_event, magic=12345):
        super(TCPClient, self).__init__()
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.in_queue = in_queue
        self.out_dict = out_dict
        self.logger = logging.getLogger("tcp client")
        self.stop_event = stop_event
        self.magic = magic
        self.name = "tcp client"

    def run(self):
        # TODO: add error handling
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((self.socks_host, self.socks_port))
        remote_socket.settimeout(5)

        s = threading.Thread(target=self.send_to_server, args=(self.in_queue,
                                                               remote_socket,))
        s.start()
        s.join()
        remote_socket.shutdown(socket.SHUT_RDWR)
        remote_socket.close()

    def send_to_server(self, in_queue, socks_socket):
        while True:
            # TODO: add conn alive func
            if not in_queue.empty():
                try:
                    tcp_data = in_queue.get()
                    self.logger.debug("got data plum packet to send over socks:\n{}".format(":".join("{:02x}".format(
                        ord(c)) for c in bytes(tcp_data[Raw]))))
                    socks_socket.sendall(bytes(tcp_data[Raw]))
                    # # spawn new thread for receive data
                    # get_data_thread = threading.Thread(target=self.get_data,
                    #                                    args=(tcp_data, socks_socket,))
                    # get_data_thread.start()
                    while True:
                        try:
                            tcp_res = socks_socket.recv(1024)
                            if tcp_res is ' ' or not tcp_res:
                                break
                            plum_data_response = plumberpacket_data_res(tcp_res, tcp_data)
                            self.out_dict.insert_plumber_pkt_to_list(plum_data_response)
                        except socket.timeout:
                            break
                        except:
                            break

                except Exception as ex:
                    logging.exception("sending to socks server failed")
                    traceback.print_exc()
                    continue

    def get_data(self, old_pkt, socks_socket):
        while not self.stop_event.is_set():
            try:
                tcp_res = socks_socket.recv(1024)
                if tcp_res is ' ' or not tcp_res:
                    break
                plum_data_response = plumberpacket_data_res(tcp_res, old_pkt)
                self.out_dict.insert_plumber_pkt_to_list(plum_data_response)
            except socket.timeout:
                break
            except:
                break
