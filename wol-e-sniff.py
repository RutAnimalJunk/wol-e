########################################################################
# Contact:              Nathaniel Carew (njcarew [at] gmail [.] com)
# Company:              http://www.senseofsecurity.com.au/
# Purpose:              Sniff the network for Wake on LAN traffic
# Version:              1.0
# Code Repo:		http://code.google.com/p/wol-e
# Credit:		Andrew Trusty for an example pcapy usage script
########################################################################

import pcapy
import time
import sys
from impacket.ImpactDecoder import *

if len(sys.argv) < 2:
   print "\t[*] Please specify an adapter collect the WOL passwords from. Eg eth1"
   sys.exit(2)

print "\t[*] WOL packet sniffing has started [*]"
# list all the network devices
pcapy.findalldevs()

interface = sys.argv[1]
max_bytes = 1024
promiscuous = False
read_timeout = 100 # in milliseconds
pc = pcapy.open_live(interface, max_bytes, promiscuous, read_timeout)
     
pc.setfilter('udp')

# callback for received packets
def recv_pkts(hdr, data):
    packet = EthDecoder().decode(data)
    a = open("output.txt", "w") 
    packet = str(packet)
    a.write(packet) 
    a.close    
    a = open('output.txt',"r")
    lineList = a.readlines()
    a.close()
    if len(packet) < 509:
	pass
    bcastframe = str(lineList[-7])
    if len(packet) > 509 and len(packet) < 515 and 'ffff' in bcastframe:
        packet = str(packet)
        lastline = str(lineList[-1])
        lastline = lastline[0:14].replace(' ', '')
        print "\t[*] Detected WOL Client power on: " + lastline + ". Saving to WOLClients.txt"
	b = open("WOLClients.txt", "a")
	lastline = lastline + " has been powed on using WOL\n"
	b.write(lastline)
	b.close()
    if len(packet) > 515 and 'ffff' in bcastframe:
        packet = str(packet)
	password = packet[-7:]
	lastline = str(lineList[-1])
	lastline = lastline[0:14].replace(' ', '')
	print "\t[*] Detected WOL Client power on: " + lastline[0:2] + ":" + lastline[2:4] + ":" + lastline[4:6] + ":" + lastline[6:8] + ":" + lastline[8:10] + ":" + lastline[10:12] + "\n"
	print "\t[*] Password in Hex is: " + hex(ord(password[0])).replace('0x', '') + ":" + hex(ord(password[1])).replace('0x', '') + ":" + hex(ord(password[2])).replace('0x', '') + ":" + hex(ord(password[3])).replace('0x', '') + ":" + hex(ord(password[4])).replace('0x', '') + ":" + hex(ord(password[5])).replace('0x', '')
        b = open("WOLClients.txt", "a")
        lastline = str(lastline) + " has been powed on with a password of: " + str(password)
        b.write(lastline)
        b.close()

packet_limit = -1
pc.loop(packet_limit, recv_pkts)

