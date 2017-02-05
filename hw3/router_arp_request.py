from scapy.all import *

def send_request(ip):
	pkt = send(ARP(op=ARP.who_has, psrc="localhost", pdst=ip))
	x = sniff(filter="arp", count=10)
	print (x.summary())
	print ("Done")

p = sr1(IP(dst="www.google.com", ttl=0)/ICMP())
print "This is router IP Address : " +  p.src
print "Send arp request to router ip"
send_request(p.src)
