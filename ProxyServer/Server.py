from scapy.all import *
import Protocol

## Create a Packet Counter
counter = 0


## Define our Custom Action function
def custom_action(packet):
    global counter
    counter += 1
    return 'Packet #{}: {} ==> {}'.format(counter, packet[0][1].src, packet[0][1].dst)


## Setup sniff, filtering for IP traffic
sniff(filter="icmp", prn=custom_action)