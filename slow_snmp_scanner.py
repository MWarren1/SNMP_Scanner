#######################
## Slow SNMP Scanner ##
#######################

# tries public and private default snmp communities
# only tries private if public responds


import argparse
import re
import sys

## CLI switches
parser = argparse.ArgumentParser(prog='Slow_SNMP_Scanner', description='scans ipv4 address range for snmp devices with default communities')
parser.add_argument('--start', required=True, help='starting ipv4 address')
parser.add_argument('--end', required=True, help='endding ipv4 address')
parser.add_argument('--output', help='output file name(optional)')

args = parser.parse_args()
startip = args.start
endip = args.end
outputfile = args.output

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

## FUNCTION - SNMP get request - borrowed this function
def snmp_get(ip,oid,community):
 
  from pysnmp.entity.rfc3413.oneliner import cmdgen

  cmdGen = cmdgen.CommandGenerator()
 
  errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    cmdgen.CommunityData(community),
    cmdgen.UdpTransportTarget((ip, 161),timeout=1,retries=0),
    oid
  )
 
  # Check for errors and print out results
  if errorIndication:
    print(errorIndication)
  else:
    if errorStatus:
      print('%s at %s' % (
        errorStatus.prettyPrint(),
        errorIndex and varBinds[int(errorIndex)-1] or '?'
       )
     )
    else:
      for name, val in varBinds:
        #print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
        return val

### END OF FUNCTIONS		
 		
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

# check if output option is used
if outputfile == None:
	outputfile = "SNMP_Scanner-Output.csv"
###	Create output file
output = open(outputfile, 'w+')
output.write("IP Address,Read,Write,Device\n")
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
	print "Scanning : "+currentippretty
	
	#### SNMP READ check, using public
	readscanresults = snmp_get(currentippretty,'1.3.6.1.2.1.1.1.0','public')
	print readscanresults
	readscanresults = str(readscanresults)
	if readscanresults == 'None':
		## didnt work
		deviceresults = readscanresults
		readscanresults = "NOPE"
	else:
		## DID work
		deviceresults = readscanresults.replace('\n', ' ').replace('\r', '').replace(',', '')
		readscanresults = "WORKED"
	if readscanresults == "WORKED":
		#### SNMP WRITE check, using private. only if the read get was successful
		writescanresults = snmp_get(currentippretty,'1.3.6.1.2.1.1.1.0','private')
		print writescanresults
		writescanresults = str(writescanresults)
		if writescanresults == 'None':
			## didnt work
			writescanresults = "NOPE"
		else:
			## DID work
			writescanresults = "WORKED"
	else:
		writescanresults = "N\\A"
		
	## creating output
	outputline = currentippretty+","+readscanresults+","+writescanresults+","+deviceresults+"\n"
	output.write(outputline)

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
print "output file : "+outputfile
print "-" * 60