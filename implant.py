#!/usr/bin/env python3
# Scanner Implant - Ivan Mladenov

import netifaces
import netaddr
import socket
import struct

ifaces: list[str] = netifaces.interfaces()
subnets: list[netaddr.IPNetwork] = []
host_mac: bytes = bytes.fromhex(
    netifaces.ifaddresses('eth0')[netifaces.AF_LINK][0]['addr'].replace(':', '')
)
host_ip: bytes = socket.inet_aton(netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr'])

# Grab IPv4 ranges for each subnet for all (non-local) interfaces 
for iface in ifaces:
    if iface == 'lo':
        continue
    
    addr = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    subnet = netaddr.IPNetwork(addr['addr'])
    subnet.netmask = (addr['netmask'])
    subnets.append(subnet)


# ARP frame without target IP (fill in as needed)
ethernet_header  = b'\xFF\xFF\xFF\xFF\xFF\xFF'  # Broadcast MAC
ethernet_header += host_mac 
ethernet_header += b'\x08\x06'                  # Ethernet type
arp_packet  = b'\x00\x01'                       # Ethernet type
arp_packet += b'\x08\x00'                       # IP protocol
arp_packet += b'\x06'                           # MAC size
arp_packet += b'\x04'                           # IP size
arp_packet += host_mac
arp_packet += host_ip
arp_packet += b'\x00\x00\x00\x00\x00\x00'       # Target MAC
frame = ethernet_header + arp_packet

for subnet in subnets:
    for ip in subnet:
        print(socket.inet_aton(str(ip)))
