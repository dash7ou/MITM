import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    '''
        first argument is interface you want to do sniffer on it
        second one is store in momery we say no
        thrid is callback function every time this function capture a backet
        filter if you look for udp or tcp ot arp or port (80/21/...)
    '''
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)


sniff("eth0")
