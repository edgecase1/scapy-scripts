#! /usr/bin/env python
from scapy.all import *

def arp_monitor_callback(pkt):
	print pkt.show()

sniff(prn=arp_monitor_callback, filter="dns", store=0)
