import sys
sys.path.append('../')
import threading
import random


class ClientNotFoundInDict(Exception):
    pass


# key = ip, value = counter(positive integer)
class ClientsDict(object):
    def __init__(self):
        self.clients_dict = dict()
        self.mutex = threading.Lock()

    def incoming_packet(self, plum_pkt):
        key = plum_pkt.src_ip
        self.increment_requests_counter(key)

    def outgoing_packet(self, plum_pkt):
        key = plum_pkt.src_ip
        if key in self.clients_dict.keys() and self.clients_dict[key] == 1:
            self.pop_key_from_dict(key)
        else:
            self.decrement_requests_counter(key)

    def pop_key_from_dict(self, key):
        try:
            self.mutex.acquire()
            self.clients_dict.pop(key)
            self.mutex.release()
        except:
            self.mutex.release()

    def increment_requests_counter(self, key):
        try:
            self.mutex.acquire()
            if key in self.clients_dict.keys():
                self.clients_dict[key] = self.clients_dict[key] + 1
            else:
                self.clients_dict[key] = 1
            self.mutex.release()
        except:
            self.mutex.release()

    def decrement_requests_counter(self, key):
        try:
            self.mutex.acquire()
            if key in self.clients_dict.keys() and self.clients_dict[key] > 1:
                self.clients_dict[key] = self.clients_dict[key] - 1
            self.mutex.release()
        except:
            self.mutex.release()

    def is_empty(self):
        if len(self.clients_dict.keys()) == 0:
            return True
        else:
            return False

    def get_waiting_client(self, outgoing_keys_list):
        if not self.is_empty() and len(outgoing_keys_list) > 0:
            keys = list(set(self.clients_dict.keys()).intersection(outgoing_keys_list))
            random_key = random.choice(keys)
            return random_key
        else:
            raise ClientNotFoundInDict()
