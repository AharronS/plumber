from scapy.all import *

def custom_action(packet):

    return packet.show2()


sniff(filter="tcp and host 216.58.208.46 or host 172.217.23.142",
      prn=custom_action)