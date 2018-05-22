import sys
sys.path.append('../')
from PlumberDataTypes import *
from scapy.all import *
import logging
from OutgoingCovertThread import OutgoingCovertThread
import threading


# get old plumber packet(sorce packet)
# wrap the new data with the old data from the old plumber packets
def plumberpacket_data_res(tcp_data, old_plum_pkt):
    plumber_pkt = DataPacket()
    plumber_pkt.message_target = "client"
    plumber_pkt.magic = old_plum_pkt.magic
    plumber_pkt.message_type = old_plum_pkt.message_type
    plumber_pkt.ip, plumber_pkt.src_ip = old_plum_pkt.ip, old_plum_pkt.src_ip
    plumber_pkt.id, plumber_pkt.seq = old_plum_pkt.id, old_plum_pkt.seq
    return plumber_pkt / tcp_data


"""
TCPClient - 
The role of this thread is to manage the connection agnaist the socks servers 
"""


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
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((self.socks_host, self.socks_port))
        remote_socket.settimeout(5)

        # spwan new thread for sending and receiving data from socks server
        s = threading.Thread(target=self.send_to_server, args=(self.in_queue,
                                                               remote_socket,))
        s.start()
        s.join()
        remote_socket.shutdown(socket.SHUT_RDWR)
        remote_socket.close()

    def send_to_server(self, in_queue, socks_socket):
        while True:
            if not in_queue.empty():
                try:
                    # get data from queue
                    tcp_data = in_queue.get()
                    self.logger.debug("got data plum packet to send over socks:\n{}".format(":".join("{:02x}".format(
                        ord(c)) for c in bytes(tcp_data[Raw]))))
                    # send the data to the socks server
                    socks_socket.sendall(bytes(tcp_data[Raw]))
                    while True:
                        try:
                            # try to get response
                            tcp_res = socks_socket.recv(1024)
                            if tcp_res is ' ' or not tcp_res:
                                break
                            # if we got response, wrap this response with relevant
                            # plumber packet data
                            plum_data_response = plumberpacket_data_res(tcp_res, tcp_data)
                            # insert the data to the out_dictionary
                            self.out_dict.insert_plumber_pkt_to_list(plum_data_response)
                        except socket.timeout:
                            break
                        except:
                            break

                except Exception as ex:
                    logging.exception("sending to socks server failed")
                    traceback.print_exc()
                    continue


