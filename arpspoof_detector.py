# !/usr/bin/env python

import scapy.all as scapy


def get_mac(ip):
    # send packet
    arp_request = scapy.ARP(pdst=ip)
    # create broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boradcast = broadcast/arp_request

    # srp send and get response to get mac_target
    answared = scapy.srp(arp_request_boradcast, timeout=10, verbose=False)[0]
    try:
        return answared[0][1].hwsrc
    except:
        get_mac(ip)


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    try:
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print('[+] You are under attack')
    except IndexError:
        pass


sniff("eth0")
