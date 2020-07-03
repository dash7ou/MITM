# !/usr/bin/env python

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    '''
        packet.accept() accept the packet and connection throw
        packet.drop() cut the internet connection :)
        packet.get_payload() show all info about packet like scapy
        but we need scapy to add packet to it because i need to deal with this packet as snifft
    '''

    # here we add packet to IP layer in scapy
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet.show())
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
