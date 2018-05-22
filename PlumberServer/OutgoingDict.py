import sys
sys.path.append('../')
import threading
import Queue
import random


class ClientNotFoundInDict(Exception):
    pass


"""
OutgoingDict - 
the role of this object is to manage the data.
for every client(ip), there is queue.
This way you can manage multiple connections and poll requests
"""


class OutgoingDict(object):
    def __init__(self):
        self.out_dict = dict()
        self.mutex = threading.Lock()

    # get plumber packet and insert the packet to the dict
    def insert_plumber_pkt_to_list(self, plum_pkt):
        key = plum_pkt.src_ip
        value = plum_pkt
        if key in self.out_dict.keys():
            self.add_element_to_dict(key, value)
        else:
            # init new queue for the new client
            queue = Queue.Queue()
            queue.put(value)
            self.add_element_to_dict(key, queue)

    # mutual exclusion needed because the access to the dict from multiple threads
    # delete key from outgoing dictionary
    def pop_key_from_dict(self, key):
        try:
            self.mutex.acquire()
            self.out_dict.pop(key)
            self.mutex.release()
        except:
            self.mutex.release()

    # mutual exclusion needed because the access to the dict from multiple threads
    # add element to dictionary
    def add_element_to_dict(self, key, value):
        try:
            self.mutex.acquire()
            if key in self.out_dict.keys():
                self.out_dict[key].put(value)
            else:
                # if the client is new
                self.out_dict[key] = value
            self.mutex.release()
        except:
            self.mutex.release()

    # get packet from dictionary
    def get_element_from_dict(self, key):
        try:
            if key in self.out_dict.keys():
                self.mutex.acquire()
                element = self.out_dict[key].get()
                self.mutex.release()
                return element
            return None
        except:
            self.mutex.release()

    # get plumber packet
    # check if after pop element the Queue is empty
    def get_plumber_pkt_from_dict_by_key(self, key):
        if key in self.out_dict.keys():
            if not self.out_dict[key].empty():
                pkt = self.get_element_from_dict(key)
                if self.out_dict[key].empty():
                    self.pop_key_from_dict(key)
                return pkt
            self.pop_key_from_dict(key)
            raise ClientNotFoundInDict()
        else:
            raise ClientNotFoundInDict()

    # get packet by src ip of plumber packet
    def get_plumber_pkt_from_dict_by_pkt(self, plum_pkt):
        key = plum_pkt.src_ip
        return self.get_plumber_pkt_from_dict_by_key(key)

    # get plumber packet
    def get_plumber_pkt_from_dict(self):
        if not self.is_out_dict_empty():
            random_key = random.choice(self.out_dict.keys())
            return self.get_plumber_pkt_from_dict_by_key(self.out_dict, random_key)
        else:
            raise ClientNotFoundInDict()

    # check if the dictionary empty
    def is_out_dict_empty(self):
        if len(self.out_dict.keys()) == 0:
            return True
        else:
            return False

    # check if client exist
    def is_client_exist(self, key):
        if key in self.out_dict.keys():
            return True
        else:
            return False

    # get all clients
    def get_all_outgoing_keys(self):
        return self.out_dict.keys()
