#!/usr/bin/env python3
# Scanner Implant - Ivan Mladenov

import asyncio
import json
import netifaces
import netaddr
import socket
import struct

arp_responses = {}
machines = {}

# Returns inet IP range for each iface
def get_inets():
    ifaces = netifaces.interfaces()
    inets = {} 

    for iface in ifaces:
        if iface == 'lo':
            continue

        arp_responses[iface] = []

        device_inet = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        device_link = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]

        machines[iface] = {}
        machines[iface][str(netaddr.IPAddress(device_inet['addr']))] = {
                "MAC": device_link['addr'], "tcp": {}
            }

        inet = netaddr.IPNetwork(device_inet['addr'])
        inet.netmask = device_inet['netmask']
        inets[iface] = inet[:-1] # exclude broadcast
    
    return inets
        
# Builds ARP frame excluding the target IP address
def build_frame():
    host_mac: bytes = bytes.fromhex(
        netifaces.ifaddresses('eth0')[netifaces.AF_LINK][0]['addr']
        .replace(':', '')
    )
    host_ip: bytes = socket.inet_aton(
        netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr']
    )

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
    
    return ethernet_header + arp_packet

async def receiver(sock, iface):
    loop = asyncio.get_running_loop()

    while True:
        data = await loop.sock_recv(sock, 4096)
        arp_responses[iface].append(data)

async def sender(sock, ips):
    frame = build_frame()

    for ip in ips:
        new_frame = frame + socket.inet_aton(str(ip))
        sock.send(new_frame)
        await asyncio.sleep(0)

async def arp_scan():
    sock = socket.socket(
        socket.PF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(socket.ETHERTYPE_ARP)
    )
    sock.setblocking(False)

    inets = get_inets()

    # TODO: Spawn thread for each iface
    for iface, inet in inets.items():
        sock.bind((iface, 0))
        recv_task = asyncio.create_task(receiver(sock, iface))
        print('[ARP] Scanning ' + iface)

        await sender(sock, inet)
        await asyncio.sleep(3) # poll for last packets

        recv_task.cancel()

def parse_arp_responses():
    for iface, packets in arp_responses.items():
        for packet in packets:
            fields = struct.unpack('!6s6s2s8s6s4s10s', packet[0:42])
            response_mac = fields[1].hex(':')
            response_ip = str(
                netaddr.IPAddress(int.from_bytes(fields[5], byteorder='big'))
            )

            machines[iface][response_ip] = {'MAC': response_mac, 'tcp': {}}

def tcp_syn_scan():
    raise NotImplementedError 

if __name__ == "__main__":
    asyncio.run(arp_scan())
    parse_arp_responses()
    
    results = {'routers': {}, 'machines': machines}
    print(json.dumps(results, indent=4))
