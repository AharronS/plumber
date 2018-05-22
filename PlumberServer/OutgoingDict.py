import sys
sys.path.append('../')
import threading
import Queue
import random


class ClientNotFoundInDict(Exception):
    pass


class OutgoingDict(object):
    def __init__(self):
        self.out_dict = dict()
        self.mutex = threading.Lock()

    def insert_plumber_pkt_to_list(self, plum_pkt):
        key = plum_pkt.src_ip
        value = plum_pkt
        if key in self.out_dict.keys():
            self.add_element_to_dict(key, value)
        else:
            queue = Queue.Queue()
            queue.put(value)
            self.add_element_to_dict(key, queue)

    def pop_key_from_dict(self, key):
        try:
            self.mutex.acquire()
            self.out_dict.pop(key)
            self.mutex.release()
        except:
            self.mutex.release()

    def add_element_to_dict(self, key, value):
        try:
            self.mutex.acquire()
            if key in self.out_dict.keys():
                self.out_dict[key].put(value)
            else:
                self.out_dict[key] = value
            self.mutex.release()
        except:
            self.mutex.release()

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

    def get_plumber_pkt_from_dict_by_pkt(self, plum_pkt):
        key = plum_pkt.src_ip
        return self.get_plumber_pkt_from_dict_by_key(key)

    def get_plumber_pkt_from_dict(self):
        if not self.is_out_dict_empty():
            random_key = random.choice(self.out_dict.keys())
            return self.get_plumber_pkt_from_dict_by_key(self.out_dict, random_key)
        else:
            raise ClientNotFoundInDict()

    def is_out_dict_empty(self):
        if len(self.out_dict.keys()) == 0:
            return True
        else:
            return False

    def is_client_exist(self, key):
        if key in self.out_dict.keys():
            return True
        else:
            return False

    def get_all_outgoing_keys(self):
        return self.out_dict.keys()
