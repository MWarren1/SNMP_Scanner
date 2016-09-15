##################
## SNMP Scanner ##
##################

import argparse
import re
import sys
import udp
import socket

## CLI switches
parser = argparse.ArgumentParser(prog='SNMP_Scanner', description='scans ipv4 address range for snmp devices with default communities')
parser.add_argument('--start', required=True, help='starting ipv4 address')
parser.add_argument('--end', required=True, help='endding ipv4 address')
parser.add_argument('--community', help='SNMP community(default is public)')
parser.add_argument('--collectorport', help='port collector is listening on(default is 55555)')

args = parser.parse_args()
startip = args.start
endip = args.end
collector_port = args.collectorport
community = args.community
if community is None:
	community = "public"

### START OF FUNCTIONS

## FUNCTION - check ip addresses are correct format
def ipcheck(input):
	ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', input )
	if len(ip) != 0:	
		ip = str(ip)
		ip = ip[2:-2]
		error = 0
	else:
		error = 1
				
	return ip,error;

## FUNCTION - next ip address
def next_ip(currentip):
	# start with last oct
	currentip[3] = currentip[3]+1
	if currentip[3] == 256:
		currentip[3] = 0
		currentip[2] = currentip[2]+1
		if currentip[2] == 256:
			currentip[2] = 0
			currentip[1] = currentip[1]+1
			if currentip[1] == 256:
				currentip[1] = 0
				currentip[0] = currentip[0]+1
	return currentip[0],currentip[1],currentip[2],currentip[3],

### END OF FUNCTIONS		

# creates get request packet
start_of_packet = "\x30\x29\x02\x01\x01\x04\x06"
end_of_packet = "\xa0\x1c\x02\x04\x00\xd8\x31\xc9\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
p_comm_len = len(community)

if p_comm_len == 3:
	p_comm_len_hex = "\x03" 
	p_total_len_hex = "\x26"
elif p_comm_len == 4:
	p_comm_len_hex = "\x04" 
	p_total_len_hex = "\x27"
elif p_comm_len == 5:
	p_comm_len_hex = "\x05" 
	p_total_len_hex = "\x28"
elif p_comm_len == 6:
	p_comm_len_hex = "\x06" 
	p_total_len_hex = "\x29"
elif p_comm_len == 7:
	p_comm_len_hex = "\x07" 
	p_total_len_hex = "\x2a"	
elif p_comm_len == 8:
	p_comm_len_hex = "\x08" 
	p_total_len_hex = "\x2b"
elif p_comm_len == 9:
	p_comm_len_hex = "\x09" 
	p_total_len_hex = "\x2c"
elif p_comm_len == 10:
	p_comm_len_hex = "\x0a" 
	p_total_len_hex = "\x2c"

packet_data = "\x30"+p_total_len_hex+"\x02\x01\x01"+"\x04"+p_comm_len_hex+community+end_of_packet
 
# check ip addresses are correct format
firstipcheck = ipcheck(startip)
endipcheck = ipcheck(endip)

if firstipcheck[1] == 1 or endipcheck[1] == 1:
	print "-" * 60
	sys.exit("***ERROR*** - one of the ip addresses is invalid")
	print "-" * 60
# map ip addresses to a list of int's
startip = firstipcheck[0]
startip = map(int, startip.split('.'))
endip = endipcheck[0]
endip = map(int, endip.split('.'))
# Check starting ip address is smaller than the end ip address
if endip < startip:
	print "-" * 60
	sys.exit("***ERROR*** - Start ip address is less than the end ip address")
	print "-" * 60

# check if port option is used
if collector_port == None:
	collector_port = 55555
else:
	collector_port = int(collector_port)
# starting scan
print "\n"
print "-" * 60
print "Starting scan from "+str(startip[0])+"."+str(startip[1])+"."+str(startip[2])+"."+str(startip[3])+" to "+str(endip[0])+"."+str(endip[1])+"."+str(endip[2])+"."+str(endip[3])
print "-" * 60
print "\n"
# setting up the scan
currentip = startip
count = 0
loop = "keep_going"

while loop == "keep_going":
	# put scan stuff here
	currentippretty = str(currentip[0])+"."+str(currentip[1])+"."+str(currentip[2])+"."+str(currentip[3])
	print "Sending request : "+currentippretty

	# build UPD packet
	udp_packet = udp.Packet()
	udp_packet.sport = collector_port;
	udp_packet.dport = 161;
	udp_packet.data = packet_data
	packet = udp.assemble(udp_packet, 0)

	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
	ret = sock.sendto(packet, (currentippretty, 0))
	print "sent %d bytes" % ret
	sock.close()

	# change currentip to next ip address
	currentip = next_ip(currentip)
	currentip = list(currentip)
	# check if it has got to the end of the scan range
	if currentip > endip:
		loop = "finished"
	# increase count of ip addresses scanned
	count = count + 1

# finish up the scan
print "\n"
print "-" * 60
print str(count)+" IP addresses were scanned\n"
print "-" * 60
