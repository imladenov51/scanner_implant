#!/usr/bin/env python3
# Scanner Implant - Ivan Mladenov

import netifaces
import netaddr
import socket
import struct

# Grab IPv4 ranges for each subnet for all (non-local) interfaces
def get_subnets() -> list[netaddr.IPNetwork]:
    ifaces = netifaces.interfaces()
    subnets = []

    for iface in ifaces:
        if iface == 'lo':
            continue
        
        addr = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        subnet = netaddr.IPNetwork(addr['addr'])
        subnet.netmask = (addr['netmask'])
        subnets.append(subnet[:-1]) # strip broadcast IP

    return subnets

# ARP frame without target IP (fill in as needed)
def build_frame() -> bytes:
    host_mac: bytes = bytes.fromhex(
        netifaces.ifaddresses('eth0')[netifaces.AF_LINK][0]['addr'].replace(':', '')
    )
    host_ip: bytes = socket.inet_aton(netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr'])

    ethernet_header  = b'\xFF\xFF\xFF\xFF\xFF\xFF'  # Broadcast MAC
    ethernet_header += host_mac 
    ethernet_header += b'\x08\x06'                  # ARP type
    arp_packet  = b'\x00\x01'                       # Ethernet type
    arp_packet += b'\x08\x00'                       # IP protocol
    arp_packet += b'\x06'                           # MAC size
    arp_packet += b'\x04'                           # IP size
    arp_packet += b'\x00\x01'                       # Operation type
    arp_packet += host_mac
    arp_packet += host_ip
    arp_packet += b'\x00\x00\x00\x00\x00\x00'       # Target MAC
    frame = ethernet_header + arp_packet
    return frame

# TODO: Read response, parallelize 
def run_scan() -> None:
    subnets = get_subnets()
    frame = build_frame()

    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.bind(('eth0', 0))

    for subnet in subnets:
        for ip in subnet:
            target_ip = socket.inet_aton(str(ip))
            new_frame = frame + target_ip
            sock.send(new_frame)

    sock.close()

if __name__ == "__main__":
    run_scan()
