#! /usr/bin/env python
from scapy.all import *
import binascii

SRC_IP="192.168.1.2"
DST_IP="192.168.1.1"
HONEY_IP="1.1.1.1"

def monitor_callback(pkt):
        print pkt.summary()
	if DNS in pkt and pkt.haslayer(DNSQR) and pkt[IP].dst == SRC_IP:
		print "dns"
		response = IP(src=SRC_IP, dst=DST_IP)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=HONEY_IP))
		send(response)
		return

	if UDP in pkt and pkt[UDP].dport == 48957:
		print "got it: " + binascii.hexlify(str(pkt[UDP].load))
		payload = pkt[UDP].load # "A"*8
		response = IP(src=HONEY_IP, dst=DST_IP)/UDP(sport=48957, dport=pkt[UDP].sport)/payload
		send(response)
		print "sent."
		return


sniff(prn=monitor_callback, filter="udp", store=0)
