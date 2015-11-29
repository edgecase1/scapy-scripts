#!/bin/bash

from scapy.all import *

import threading
import time

import signal
import sys

myAPs = [ '00:0c:42:6c:5b:ed', '00:0c:42:6c:5b:e0', '00:0c:42:6c:5b:f7', '00:0c:42:6b:2a:75', '00:0c:42:6b:2a:7f', '00:0c:42:6c:5b:c2', '00:0c:42:6b:2b:33', '00:0c:42:6c:5b:c1', '00:0c:42:6c:5c:1b' ]



class Host():

	ip=None
	mac=None
	ap=None

	def __init__(self, mac, ip):
		self.ip = ip
		self.mac = mac

	def __str__(self):
		return "<host:" + str(self.ip) + " " + self.mac + ">"

class AP():
	mac=None
	hosts = []

	def __init__(self, mac):
		self.mac = mac

	def add_host(self, host):
		if host.ap != None and host.ap != self:
			host.ap.hosts.remove(host)
			host.ap=self
			
		if not host in self.hosts:
			self.hosts.append(host)

	
	def __str__(self):
		s = "<ap:" + str(self.mac) + ": "
		for i in self.hosts:
			s += str(i)
			s += ","
		s += ">"
		return s

class Harvester():
	
	def __init__(self):
		self.IPs = {}

	def collect_ip(self, ip):
		if ip in self.IPs:
			self.IPs[ip] += 1
		else:
			self.IPs[ip] = 1

	def __str__(self):
		return self.IPs.__str__()

def signal_handler(signal, frame):
        print 'You pressed Ctrl+C!'
	output_thread.shutdown()
	output_thread.join()
        sys.exit(0)

class OutputThread(threading.Thread):

	def __init__(self, output_path):
		threading.Thread.__init__(self)
		self.output_file = open(output_path, 'w')
		self.stop = False

	def set_feed(self, obj):
		self.output_feed = obj

	def run(self):
		while 1:
			#self.output_file.write("self.output_feed.read")
			#print self.output_feed
			print f
			if self.stop:
				break
			time.sleep(5)
	
	def shutdown(self):
		self.stop = True


class Factory():

	def __init__(self):
		self.APs = {}
		self.HOSTS = {}

	def add_ap(self, mac):
		if not mac in self.APs:
			ap = AP(mac)
			self.APs[mac] = ap
			return ap
		else:
			return self.APs[mac]
		
	def add_host(self, mac, ip):
		if not ip in self.HOSTS:
			host = Host(mac, ip)
			self.HOSTS[ip] = host
			return host
		else:
			return self.HOSTS[ip]


	def add(self, host_mac, host_ip, ap_mac):
		ap = self.add_ap(ap_mac)
		host = self.add_host(host_mac, host_ip)
		ap.add_host(host)
		print ap
		print host

	def __str__(self):
		s = ""
		for i in self.HOSTS.values():
			s += str(i)
		return s

def handle(p):
	eth=p
	if not p.payload.__class__ == scapy.layers.inet.IP:
		# should not happen!
		return
	ip=p.payload
	#if not ip.payload.__class__ == scapy.layers.inet.TCP:
	#	return
	#tcp=ip.payload
	# fields dport sport
#if tcp.fields['dport'] in [ 80, 443 ]:
#	print eth.fields['src'], ip.fields['src'], tcp.fields['dport']
#print "got " + ip.fields['src']
	harverster.collect_ip(ip.src)


	f.add(eth.src, ip.src, eth.dst)

f = Factory()
harverster = Harvester()
output_thread = OutputThread("ips")
output_thread.set_feed(harverster)
sniff(prn=handle, filter="ip", store=0)
signal.signal(signal.SIGINT, signal_handler)
output_thread.start()
signal.pause()
