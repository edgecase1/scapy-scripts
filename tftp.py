

from scapy.all import *




def fire(payload):
	p = IP(dst="10.10.76.13")
	p /= UDP(dport=69, sport=5555)
	p /= payload
	r = sr1(p)
	r.show()

filename=""
req_type="\x00\x01"
payload= req_type + filename + "\x00" + "netascii" + "\x00"
fire(payload)

