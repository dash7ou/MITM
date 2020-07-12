import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    try:
        packet[scapy.Raw].load = load
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        print(packet.show())
        return packet
    except Exception:
        raise Exception("Error")


def process_packet(packet):
    try:
        '''
            res not html code but come with gzip incoding
        '''
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):

            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] Request ")
                if scapy_packet[scapy.Raw]:
                    print(scapy_packet.show())
                    modified_load = re.sub(r"Accept-Encoding:.*?\\r\\n", "",
                                           str(scapy_packet[scapy.Raw].load))
                    print(modified_load)
                    # new_packet = set_load(
                    #     scapy_packet, re.sub(r"b'|'", '', modified_load))

                    # packet.set_payload(bytes(new_packet))
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Response")
                # print(scapy_packet.show())

        packet.accept()
    except Exception as e:
        print(f"[+] Error => {e}")
        packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
