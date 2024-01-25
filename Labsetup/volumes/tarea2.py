#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'novillo%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

#Configurar la interfaz TUN
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))


while True:
 # Get a packet from the tun interface
 packet = os.read(tun, 2048)
 if packet:
  pkt = IP(packet)
  print("{}:".format(ifname),pkt.summary())
  #  Task 2.d: Write to the TUN Interface
  # sniff and print out icmp echo request packet
  if ICMP in pkt and pkt[ICMP].type == 8:
    print("Original Packet.........")
    print("Source IP : ", pkt[IP].src)
    print("Destination IP :", pkt[IP].dst)
    # spoof an icmp echo reply packet
    # swap srcip and dstip
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
    icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
    data = pkt[Raw].load
    newpkt = ip/icmp/data

    print("Spoofed Packet.........")
    print("Source IP : ", newpkt[IP].src)
    print("Destination IP :", newpkt[IP].dst)
		
    os.write(tun, bytes(newpkt))
