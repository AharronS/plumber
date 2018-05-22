import sys
sys.path.append('../')
import threading
import random


class ClientNotFoundInDict(Exception):
    pass


"""
ClientsDict  - 
The role of the class is to manage all the clients connections
"""


class ClientsDict(object):
    def __init__(self):
        self.clients_dict = dict()
        self.mutex = threading.Lock()

    # get packet and increment the counter of the ip key
    def incoming_packet(self, plum_pkt):
        key = plum_pkt.src_ip
        self.increment_requests_counter(key)

    # get packet and decrement the counter of the ip key
    def outgoing_packet(self, plum_pkt):
        key = plum_pkt.src_ip
        if key in self.clients_dict.keys() and self.clients_dict[key] == 1:
            self.pop_key_from_dict(key)
        else:
            self.decrement_requests_counter(key)

    # mutual exclusion needed because the access to the dict from multiple threads
    # the role of this function is to delete key from dictionary
    def pop_key_from_dict(self, key):
        try:
            self.mutex.acquire()
            self.clients_dict.pop(key)
            self.mutex.release()
        except:
            self.mutex.release()

    # mutual exclusion needed because the access to the dict from multiple threads
    # the role of this function is to increment the client counter
    def increment_requests_counter(self, key):
        try:
            self.mutex.acquire()
            if key in self.clients_dict.keys():
                self.clients_dict[key] = self.clients_dict[key] + 1
            else:
                # if it is new connection, assign value
                self.clients_dict[key] = 1
            self.mutex.release()
        except:
            self.mutex.release()

    # mutual exclusion needed because the access to the dict from multiple threads
    # the role of this function is to decrement the client counter
    def decrement_requests_counter(self, key):
        try:
            self.mutex.acquire()
            if key in self.clients_dict.keys() and self.clients_dict[key] > 1:
                self.clients_dict[key] = self.clients_dict[key] - 1
            self.mutex.release()
        except:
            self.mutex.release()

    # check if dict is empty
    def is_empty(self):
        if len(self.clients_dict.keys()) == 0:
            return True
        else:
            return False

    # get all clients that have waiting data, and the clients that
    # send poll request or data request
    def get_waiting_client(self, outgoing_keys_list):
        if not self.is_empty() and len(outgoing_keys_list) > 0:
            keys = list(set(self.clients_dict.keys()).intersection(outgoing_keys_list))
            random_key = random.choice(keys)
            return random_key
        else:
            raise ClientNotFoundInDict()
