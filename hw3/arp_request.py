from scapy.all import *

def send_request(ip):
	pkt = send(ARP(op=ARP.who_has, psrc="localhost", pdst=ip))
	x = sniff(filter="arp", count=10)
	print (x.summary())
	print ("Done")


input_ip = raw_input("Input IP address : ")
send_request(input_ip)
