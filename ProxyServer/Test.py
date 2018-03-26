from scapy.all import *
import threading
import time

exitFlag = 0


class ICMPEchoRequestThread(threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter


    def run(self):
        print "Starting " + self.name
        sniff(filter="icmp", prn=self.dissect_packet())
        print "Exiting " + self.name

    def dissect_packet(self):
        def custom_action(packet):
            packet.show2()
        return custom_action


class TCPThread(threading.Thread):
    def __init__(self, thread_id, name, counter):
        threading.Thread.__init__(self)
        self.threadID = thread_id
        self.name = name
        self.counter = counter

    def run(self):
        print "Starting " + self.name
        sniff(filter="tcp", prn=self.dissect_packet())
        print "Exiting " + self.name

    def dissect_packet(self):
        print self.name + "\n\n\n\n"

        def custom_action(packet):
            packet.show2()

        return custom_action


# Create new threads
thread1 = ICMPEchoRequestThread(1, "Thread-1", 1)
thread2 = TCPThread(2, "Thread-2", 2)

# Start new Threads
thread1.start()
thread2.start()

print "Exiting Main Thread"
