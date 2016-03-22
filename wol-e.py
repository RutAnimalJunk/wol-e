#!/usr/bin/python
########################################################################
# Contact:              Nathaniel Carew (njcarew [at] gmail [.] com)
# Company:              http://www.senseofsecurity.com.au/
# Purpose:              Tools to target the Wake On LAN feature.
# Version:              1.0
# Code Repo:            http://code.google.com/p/wol-e
# Credits:              Fadly Tabrani for WOL example
#			Andrew Trusty for pcapy example
########################################################################

import struct
import socket
import sys
import os
import datetime
import time
import math
import scapy.utils
import scapy.layers.l2
import scapy.route
import scapy

def wake_on_lan(version):

# search for Apple MAC addresses in the network and place them into AppleTargets.txt for future use.
    if sys.argv[1] == "-f":
	print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - Scan for Apple devices.\n"

        def long2net(arg):
            if (arg <= 0 or arg >= 0xFFFFFFFF):
                raise ValueError("illegal netmask value", hex(arg))
            return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

        def to_CIDR_notation(bytes_network, bytes_netmask):
            network = scapy.utils.ltoa(bytes_network)
            netmask = long2net(bytes_netmask)
            net = "%s/%s" % (network,netmask)
            if netmask < 20:
                print net, "is too big. skipping"
                return None

            return net

        def scan_and_print_neighbors(net, interface):
            print "arping", net, "on", interface
            ans,unans = scapy.layers.l2.arping(net, iface=interface, timeout=1, verbose=True)
            d=open('netscan.txt', 'w')
            for s,r in ans.res:
                array = []
                array.append(r.sprintf("%Ether.src% %ARP.psrc%"))
                for item in array:
                        d.write("%s\n" % item)
            d.close()

            small_file = open('netscan.txt','r')
            long_file = open('AppleMAC.lst','r')
            output_file = open('AppleTargets.txt','a')
            existing_targets = open('AppleTargets.txt','r')

            small_lines = small_file.readlines()
            small_lines_cleaned = [line.lower().rstrip() for line in small_lines]
            long_lines = long_file.readlines()
            long_lines_cleaned = [line.lower().rstrip() for line in long_lines]
            targets_lines = existing_targets.readlines()
            target_lines_cleaned = [line.lower().rstrip() for line in targets_lines]

            print "\n\n"
            for smalllines in small_lines_cleaned:
                for longlines in long_lines_cleaned:
                        if longlines in smalllines and smalllines not in target_lines_cleaned:
                                print "\t[*] Apple Device Detected: " + str(smalllines) + ". Saving to AppleTargets.txt"
                                output_file.write(str(smalllines) + "\n")
            print "\t[*] Scan completed [*]\n"
	    print "\n\n"
            small_file.close()
            long_file.close()
            output_file.close()
	    sys.exit(2)

        for route in scapy.config.conf.route.routes:

            network = route[0]
            netmask = route[1]
            interface = route[3]
    # skip loopback network and default gw
            if network == 0 or interface=='lo' or route[4] == '127.0.0.1' or route[4]=='0.0.0.0':
                continue
            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue
            net = to_CIDR_notation(network, netmask)
        if net:
            scan_and_print_neighbors(net, interface)

# Manual WOL Enabling for single addresses
    if sys.argv[1] == "-m":
	if len(sys.argv) < 3:
	    print "\n\t[*] Please specify a MAC address. [*]\n"
	    sys.exit(2)
        macaddress = sys.argv[2]
	if len(macaddress) == 12:
	    pass
	elif len(macaddress) == 12 + 5:
            sep = macaddress[2]
            macaddress = macaddress.replace(sep, '')
    	else:
	    print "\n\t[*] Please check the MAC address format. Example: 00:1A:2B:3C:4D:5E\n"
            sys.exit(2)
	if len(sys.argv) < 4:
  	    print "\n\t[*] No broadcast address or destination port detected, using the default of 255.255.255.255 and 9 respectively [*]"
	    bcast = '255.255.255.255'
	    destport = int(9)
	else:
	    bcast = sys.argv[4]
	    destport = int(sys.argv[6])
        wolpass = "0"
	if len(sys.argv) > 7:
	    wolpass = sys.argv[8]
        if len(wolpass) == 12:
	    pass
        elif len(wolpass) == 12 + 5:
            sep = wolpass[2]
            wolpass = wolpass.replace(sep, '')
	else:
	    wolpass = "empty"

	print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - Powers on computers in the network with WOL enabled.\n"
        print "\t\tMac is: " + macaddress
        print "\t\tBroadcast is: " + str(bcast)
        print "\t\tDest Port is: " + str(destport)
        print "\t\tPassword is: " + wolpass
        if wolpass != "empty":
	        data = ''.join(['FFFFFFFFFFFF', macaddress * 16, wolpass])
        else:
	        data = ''.join(['FFFFFFFFFFFF', macaddress * 16])
	send_data = ''

	for i in range(0, len(data), 2):

                send_data = ''.join([send_data,
                    struct.pack('B', int(data[i: i + 2], 16))])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(send_data, (bcast, destport))
	print "\t[*] Attempt to power on " + sys.argv[2] + " completed. Exiting [*]\n"
	sys.exit(2)

# WOL Password Sniffing Section
    if sys.argv[1] == "-s":
	print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - WOL Packet Sniffer."
        if len(sys.argv) < 3:
            print "\t[*] Please specify an adapter collect the WOL passwords from. Eg wol-e.py -s -i eth0 [*]\n"
            sys.exit(2)
	sniff = "python " + os.getcwd() + "/" + "wol-e-sniff.py " + sys.argv[3]
	sniff = str(sniff)
	os.system(sniff)

# Attempt to wake all Apple clients collected during an earlier scan using -f
    if sys.argv[1] == "-fa":
        print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - WOL Detected Apple clients."
	bcast = '255.255.255.255'
	apples = os.getcwd() + "/" + "AppleTargets.txt"
	if os.path.exists(apples) == False:
        	print "\n\t[*] Please ensure you have the AppleTargets.txt file in the current working directory.\n"
        	sys.exit(2)
	if len(sys.argv) < 3:
        	print "\n\t[*] No destination port detected, using 9 as the default"
		port = int(9)
	else:
        	print "\t[*] Custom port detected: " + str(sys.argv[3])
        	port = int(sys.argv[3])
	f=open(apples)
	linenums = 0
	for lines in f:
		linenums = linenums + 1
		macaddress = lines[0:17]
		sep = macaddress[2]
		macaddress = macaddress.replace(sep, '')
		data = ''.join(['FFFFFFFFFFFF', macaddress * 16])
		send_data = ''

		for i in range(0, len(data), 2):
	                send_data = ''.join([send_data,
        		        struct.pack('B', int(data[i: i + 2], 16))])

		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		sock.sendto(send_data, (bcast, port))
		time.sleep(0.005)
	print "\n\t[*] " + str(linenums) + " detected Apple clients have been sent WOL requests, Exiting.\n"
	f.close()
	sys.exit(2)

# WOL Bruteforcer against a list of MAC ranges (time intensive due to the amount of possible addresses)
    if sys.argv[1] == "-a":
	print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - WOL Bruteforce MAC ranges."
	bcast = '255.255.255.255'
	macs = os.getcwd() + "/" + "bfmac.lst"
    else:
	print "\n\t[*] Unknown command, please see the help documentation for more information\n"
	sys.exit(2)
    if len(sys.argv) < 3:
	print "\n\t[*] No destination port detected, using 9 as the default"
	port = int(9)
    else:
	print "\t[*] Custom port detected: " + str(sys.argv[3])
	port = int(sys.argv[3])
    if os.path.exists(macs) == False:
	print "\n\t[*] Please ensure you have the bfmac.lst file in the current working directory.\n"
	sys.exit(2)	
    else:
    	f=open(macs)
	print "\t[*] WOL Bruteforcing has started."
	for line in f:
		print "\t[*] Now bruteforcing " + str(line).rstrip() + ":00:00 -> " + str(line).rstrip() + ":FF:FF"
		for y in range(0, 255):
       			for z in range(0, 255):
       				line = line.rstrip()
				if len(line) < 11 or len(line) > 11:
					print "\n\t[*] MAC address format incorrect, please fix the contents of bfmac.lst\n\t[*] Eg: 00:12:34:46\n"
					sys.exit(2)
				macaddress = line + ":" + hex(y).replace('0x', '').zfill(2) + ":" + hex(z).replace('0x', '').zfill(2)
				sep = macaddress[2]
				macaddress = macaddress.replace(sep, '')

    				data = ''.join(['FFFFFFFFFFFF', macaddress * 16])
    				send_data = '' 

				for i in range(0, len(data), 2):
					send_data = ''.join([send_data,
                       				struct.pack('B', int(data[i: i + 2], 16))])

				sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
				sock.sendto(send_data, (bcast, port))
				time.sleep(0.001)
    	f.close()
    	print "\n\t[*] Bruteforce of MAC ranges completed. Exiting [*]\n"
    	sys.exit(2)

if __name__ == '__main__':

	version = "1.0"

	help_message = "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - A collection of WOL tools. [*]\n\t[*] by Nathaniel Carew [*]\n\n\t[*] For help use: wol-e.py -h\n"

	if len(sys.argv) < 2:
        	print help_message
        	sys.exit(2)

        if sys.argv[1] == "-h":
		bold = "\033[1m"
		nobold = "\033[0;0m"
	        print bold + "\n[*] WOL-E " + version + " [*]\n[*] Wake on LAN Explorer - A collection a WOL tools. [*]\n[*] by Nathaniel Carew [*]\n" + nobold
		print bold + "[*] Waking up single computers [*]" + nobold
		print " To wake up a single computer use the following command:"
		print bold + "\twol-e.py -m 00:12:34:56:78:90 -b 192.168.1.255 -p 9" + nobold
		print " If you do not specify a broadcast address or port wol-e will set the following as defaults for you:"
		print "\tPort: 9"
		print "\tBroadcast: 255.255.255.255"
		print " If a password is required use the -k 00:12:34:56:78:90 at the end of the above command."
		print bold + "\n[*] Sniffing the network for WOL requests and passwords [*]" + nobold
		print " To sniff the network for WOL traffic use the following command:"
		print bold + "\twol-e.py -s -i eth0" + nobold
		print " All captured WOL requests will be displayed on screen and written to WOLClients.txt."
		print bold + "\n[*] Bruteforce powering on WOL clients [*]" + nobold
		print " To bruteforce the network use the following command:"
		print bold + "\twol-e.py -a" + nobold
		print " Place the address ranges into the bfmac.lst that you wish to bruteforce. They should be in the following format:"
		print "\t00:12:34:56"
		print " If you do not specify a broadcast address or port wol-e will set the following as defaults for you:"
		print "\tPort: 9"
		print " If you wish to bruteforce a different port use the -p PORT at the end of the above command."
		print bold + "\n[*] Detecting Apple devices on the network for WOL enabling [*]" + nobold
		print " If you want to scan the network for Apple devices on your subnet use the following command:"
		print bold + "\twol-e.py -f" + nobold
		print " This will output to the screen and write to AppleTargets.txt any Apple MAC address that are detected."
                print bold + "\n[*] Attempt to wake all detected Apple targets in AppleTargets.txt [*]" + nobold
                print " If you want to attempt to wake all targets found from using -f use the following command:"
                print bold + "\twol-e.py -fa" + nobold
                print " This will send a single WOL packet to each client in the list and tell you how many clients were attempted.\n\n"
		sys.exit(2)

	wake_on_lan(version)
