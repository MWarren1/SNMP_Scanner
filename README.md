# Super Quick SNMP Scanner
###### Dependencies : Python 2.7

### ***Both Scripts need to run as admin***
###### KNOWN ISSUES
######	- port doesnt seem to matter the collector might collect DNS queries
######	- Scanner is too quick for the collector if their are alot of snmp devivces together
######	- SNMP community is only works communities with 3-10 characters

SNMP scanner made of two parts the scanner and the collector that can scan an ip address range, curretnly they must be running on the same machine

First the collector
```
usage: SNMP_Collector [-h] [--port PORT] [--log LOG]

example: SNMP_Collector.py --log SNMP_output.csv

SNMP collector used with SNMP_Scanner

optional arguments:
  -h, --help   show this help message and exit
  --port PORT  port to listen on(default is 55555)
  --log LOG    File to output info collected(default is SNMP_Collector-
               Output.csv)
``` 
The Scanner
```
SNMP_Scanner.py --help
usage: SNMP_Scanner [-h] --start START --end END [--community COMMUNITY]
                    [--collectorport COLLECTORPORT]

example: SNMP_Scanner.py --start 100.100.0.0 --end 100.100.255.255 --community public
 					
scans ipv4 address range for snmp devices

optional arguments:
  -h, --help            show this help message and exit
  --start START         starting ipv4 address
  --end END             endding ipv4 address
  --community COMMUNITY
                        SNMP community(default is public)
  --collectorport COLLECTORPORT
                        port collector is listening on(default is 55555)

```  
