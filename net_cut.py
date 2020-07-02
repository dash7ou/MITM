# !/usr/bin/env python

import netfilterqueue


def process_packet(packet):
    print(packet)
    '''
       packet.accept() accept the packet and connection throw
	packet.drop() cut the internet connection :)
    '''
    packet.drop()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
