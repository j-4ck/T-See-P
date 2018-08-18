# WORK IN PROGRESS
# NOT YET 100% FINISHED
from scapy.all import *
import socket
import sys
from datetime import datetime
import time
import netinfo
global pktnum
pktnum = 1
global tcpnum
tcpnum = 0
global udpnum
udpnum = 0
global arpnum
arpnum = 0
global icmpnum
icmpnum = 0
class default:
	netinfo.get_routes()
	default_gateway = [route for route in netinfo.get_routes() if route['dest'] == '0.0.0.0'][0]
	gateway = default_gateway['gateway']
	interface = default_gateway['dev']

def revdns(ip):
	try:
		s = socket.gethostbyaddr(ip)
		return s[0]
	except:
		return ''
def handleTCP(pkt):
	global pktnum
	global tcpnum
	tcp = pkt.payload.payload
	dst = pkt.payload.dst
	src = pkt.payload.src
	dport = str(tcp.dport)
	sport = str(tcp.sport)
	flags = str(tcp.flags)
	seq = str(tcp.seq)
	ack = str(tcp.ack)
	win = str(tcp.window)
	ops = str(tcp.options)
	length = str(len(pkt))
	endstr = ''
	try:
		if '--raw' in sys.argv or '-r' in sys.argv:
			try:
				raw = tcp.payload.load
				endstr = ', raw-load: ' + raw
			except:
				endstr = ''
	except:
		pass
	print '[' + str(pktnum) + '] [TCP] ' + src + ':' + sport + '(' + revdns(src) + ') --> ' + dst + ':' + dport + '(' + revdns(dst) + ') | flags: ' + flags + ', seq: ' + seq + ', ack: ' + ack + ', win: ' + win + ', ops: '  + ops + ', len: ' + length + endstr
	pktnum += 1
	tcpnum += 1

def handleUDP(pkt):
	global pktnum
	global udpnum
	udp = pkt.payload.payload
	dst = pkt.payload.dst
	src = pkt.payload.src
	dport = str(udp.dport)
	sport = str(udp.sport)
	flags = str(pkt.payload.flags)
	ops = str(pkt.payload.options)
	length = str(len(pkt))
	#ADD SUPPORT FOR RAW
	print '[' + str(pktnum) + '] [UDP] ' + src + ':'  + sport + '(' + revdns(src) + ') --> ' + dst + ':' + dport + '(' + revdns(dst) + ') | flags: ' + flags + ', ops: ' + ops + ', len: ' + length
	pktnum += 1
	udpnum += 1

def handleICMP(pkt):
	global pktnum
	global icmpnum
	icmp = pkt.payload.payload
	dst = pkt.payload.dst
	src = pkt.payload.src
	ttl = str(pkt.payload.ttl)
	ops = str(pkt.payload.options)
	length = str(len(pkt))
	form = icmp.type
	if icmp.type == 8:
		type = 'echo-response'
	elif icmp.type == 0:
		type = 'echo-reply'
	else:
		type = str(form)
	print '[' + str(pktnum) + '] [ICMP] ' + src + '(' + revdns(src) + ') --> ' + dst + '(' + revdns(dst) + ') | ops: ' + ops + ', ttl: ' + ttl + ', len: ' + length + ', format: ' + type
	pktnum += 1
	icmpnum += 1

def handleARP(pkt):
	global pktnum
	global arpnum
	arp = pkt.payload
	dst = arp.pdst
	src = arp.psrc
	hwdst = pkt.dst
	hwsrc = pkt.src
	length = str(len(pkt))
	type = arp.op
	if arp.op == 1:
		print '[' + str(pktnum) + '] ARP who-has ' + dst + '(' + revdns(dst) + ') says ' + src + '(' + hwsrc + '//' + revdns(src) + ') | len: ' + length
	elif arp.op == 2:
		print '[' + str(pktnum) + '] ARP is-at ' + hwsrc + ' says ' + src + '(' + revdns(src) + ') | len: ' + length
	else:
		pass
	pktnum += 1
	arpnum += 1

def dump(pkt):
	global pktnum
	global tcpnum
	global udpnum
	global arpnum
	global icmpnum
	if pkt.haslayer('TCP'):
		protoc = 'TCP'
		tcpnum += 1
	elif pkt.haslayer('UDP'):
		protoc = 'UDP'
		udpnum += 1
	elif pkt.haslayer('ARP'):
		protoc = 'ARP'
		arpnum += 1
	elif pkt.haslayer('ICMP'):
		protoc = 'ICMP'
		icmpnum += 1
	else:
		protoc = 'MAL'
	print '\n[' + str(pktnum) + '][' + protoc + ']' 
	print str(hexdump(pkt)).strip('None')
	pktnum += 1

def pktHandler(pkt):
	arg = sys.argv[1].lower()
	if arg == 'tcp':
		if pkt.haslayer('TCP'):
			handleTCP(pkt)
	elif arg == 'udp':
		if pkt.haslayer('UDP'):
			handleUDP(pkt)
	elif arg == 'icmp' or arg == 'ping':
		if pkt.haslayer('ICMP'):
			handleICMP(pkt)
	elif arg == 'arp':
		if pkt.haslayer('ARP'):
			handleARP(pkt)
	elif arg == 'hexdump' or arg == 'dump':
		dump(pkt)
	elif arg == '*' or arg == 'all':
		if pkt.haslayer('TCP'):
			handleTCP(pkt)
		elif pkt.haslayer('UDP'):
			handleUDP(pkt)
		elif pkt.haslayer('ICMP'):
			handleICMP(pkt)
		elif pkt.haslayer('ARP'):
			handleARP(pkt)

	else:
		print 'Protocol not yet supported: ' + sys.argv[1]
		time.sleep(1)
		sys.exit()
def main():
	if len(sys.argv) < 2:
		print 'Invalid arguments: ' + str(sys.argv)
		time.sleep(1)
		sys.exit()

	elif sys.argv[1].lower() == '-h':
		print 'Read "HELP.txt"!'
		time.sleep(1)
		sys.exit()
	if sys.argv[1] == '*':
		snifftype = 'ALL'
	else:
		snifftype = sys.argv[1].upper()
	if '-r' in sys.argv:
		rmode = 'Y'
	else:
		rmode = 'N'
	print '+' + '-'*60 + '>'
	print '| [' + str(datetime.now()) + '] Started sniffing for: ' + str(snifftype)
	print '| [' + str(datetime.now()) + '] TCP raw mode: ' + rmode
	print '| [' + str(datetime.now()) + '] Default interface: "' + default.interface + '"'
	print '| [' + str(datetime.now()) + '] Default gateway: "' + default.gateway + '"'
	print '| [' + str(datetime.now()) + '] Author: @0xjack'
	print '+' + '-'*60 + '>\n'
	time.sleep(1.5)
	sniff(prn=pktHandler)
	print '\n' + str(pktnum-1) + ' packets captured!\n'
	print 'TCP: ' + str(tcpnum) + ', UDP: ' + str(udpnum) + ', ARP: ' + str(arpnum) + ', ICMP: ' + str(icmpnum)

if __name__ == '__main__':
	main()
