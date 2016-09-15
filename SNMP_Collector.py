####################
## SNMP_Collector ##
####################
 
import socket
import sys
import argparse


## CLI switches
parser = argparse.ArgumentParser(prog='SNMP_Collector', description='SNMP collector used with SNMP_Scanner')
parser.add_argument('--port', help='port to listen on(default is 55555)')
parser.add_argument('--log', help='File to output info collected(default is SNMP_Collector-Output.csv)')


args = parser.parse_args()
PORT = args.port
logfile = args.log

if logfile == None:
	logfile = "SNMP_Collector-Output.csv"
if PORT == None:
	PORT = 55555
else:
	PORT = int(PORT)
HOST = ''   # Symbolic name meaning all available interfaces
print "\n"
print "#" * 60
print "SNMP_Collector"
print ""
print "					By Redemption.Man"
print "#" * 60
print "-" * 60
print "Listening on port : "+str(PORT)
print "log file : "+logfile

# Datagram (udp) socket
try :
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

except socket.error, msg :
    print 'Failed to create socket. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

 
# Bind socket to local host and port
try:
    s.bind((HOST, PORT))
except socket.error , msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
output = open(logfile, 'w+')
output.write("IP Address,Community,Device\n")     

print "-" * 60 
print "\n"
#now keep talking with the client
try:
	while 1:
		# receive data from client (data, addr)
		d = s.recvfrom(1024)
		#print d
		data = d[0]
		addr = d[1]
		data = data.replace('\n', ' ').replace('\r', '').replace(',', '')
		#data = data[80:]
		#print data
	
		if addr[0] != "8.8.8.8" or addr[0] != "8.8.4.4":
		
			output.write(addr[0]+",,"+data.strip()+","+"\n") 
			#print 'Message[' + addr[0] + ':' + str(addr[1]) + '] - ' + data.strip()
			print 'Message : '+addr[0]
except KeyboardInterrupt:
    print 'Ctrl-C Pressed -Exitting'     
s.close()
output.close()



