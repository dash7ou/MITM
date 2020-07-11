import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    '''
        as we not html response come with gzip incoding
    '''
    if scapy_packet[scapy.TCP].dport == 80:
        print("[+] Request ")
        print(scapy_packet.show())
    elif scapy_packet[scapy_packet.TCP].sport == 80:
        print("[+] Response")
        print(scapy_packet.show())
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
