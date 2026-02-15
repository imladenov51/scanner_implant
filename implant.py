#!/usr/bin/env python3
# Scanner Implant - Ivan Mladenov

import time
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
                'mac': device_link['addr'], "tcp": {}
        }

        inet = netaddr.IPNetwork(device_inet['addr'])
        inet.netmask = device_inet['netmask']
        inets[iface] = inet[:-1] # exclude broadcast
    
    return inets
        
# Builds ARP frame excluding the target IP address
def build_arp_frame(iface):
    host_mac: bytes = bytes.fromhex(
        netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
        .replace(':', '')
    )
    host_ip: bytes = socket.inet_aton(
        netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
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

async def arp_receiver(sock, iface):
    loop = asyncio.get_running_loop()

    while True:
        data = await loop.sock_recv(sock, 1024)
        arp_responses[iface].append(data)

async def arp_sender(sock, ips, iface):
    frame = build_arp_frame(iface)

    for ip in ips:
        new_frame = frame + socket.inet_aton(str(ip))
        sock.send(new_frame)
        await asyncio.sleep(0)

async def arp_scan():
    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(socket.ETHERTYPE_ARP)
    )
    sock.setblocking(False)

    inets = get_inets()

    for iface, inet in inets.items():
        sock.bind((iface, 0))
        recv_task = asyncio.create_task(arp_receiver(sock, iface))
        print('[ARP] Scanning ' + iface)

        await arp_sender(sock, inet, iface)
        await asyncio.sleep(1) # poll for last packets

        recv_task.cancel()

    sock.close()

def parse_arp_responses():
    for iface, packets in arp_responses.items():
        for packet in packets:
            fields = struct.unpack('!6s6s2s8s6s4s10s', packet[0:42])
            response_mac = fields[1].hex(':')
            response_ip = str(
                netaddr.IPAddress(int.from_bytes(fields[5], byteorder='big'))
            )

            machines[iface][response_ip] = {'mac': response_mac, 'tcp': {}}

def build_tcp_syn_frame(iface, dest_mac, dest_ip, dest_port):
    host_mac: bytes = bytes.fromhex(
        netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
        .replace(':', '')
    )
    host_ip: bytes = socket.inet_aton(
        netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    )

    ethernet_header  = dest_mac
    ethernet_header += host_mac
    ethernet_header += b'\x08\x00'

    ip_words = (
        int.from_bytes(host_ip[0:2], byteorder='big') +
        int.from_bytes(host_ip[2:4], byteorder='big') +
        int.from_bytes(dest_ip[0:2], byteorder='big') +
        int.from_bytes(dest_ip[2:4], byteorder='big')
    )

    ip_checksum = 0x4500 + 0x0028 + 0xabcd + 0x4006 + ip_words
    ip_checksum = 0xffff - ((ip_checksum & 0xffff) + (ip_checksum >> 16))
    ip_header  = b'\x45\x00\x00\x28'
    ip_header += b'\xab\xcd\x00\x00'
    ip_header += b'\x40\x06'
    ip_header += ip_checksum.to_bytes(2, byteorder='big')
    ip_header += host_ip
    ip_header += dest_ip
   
    tcp_checksum = 0
    tcp_checksum = (
        0x0006 + ip_words + 0x0014 + 0x3039 + 
        int.from_bytes(dest_port, byteorder='big') + 0x5002 + 0x7110
    )
    # TODO: handle 0x1ffff error better
    while (tcp_checksum > 0xffff):
        tcp_checksum = (tcp_checksum & 0xffff) + (tcp_checksum >> 16)
    tcp_checksum = 0xffff - tcp_checksum
    tcp_header  = b'\x30\x39'
    tcp_header += dest_port
    tcp_header += b'\x00\x00\x00\x00'
    tcp_header += b'\x00\x00\x00\x00'
    tcp_header += b'\x50\x02\x71\x10'
    tcp_header += tcp_checksum.to_bytes(2, byteorder='big')

    tcp_header += b'\x00\x00'

    return ethernet_header + ip_header + tcp_header

async def tcp_syn_receiver(sock, iface):
    loop = asyncio.get_running_loop()
    
    while True:
        data = await loop.sock_recv(sock, 1024)
        if not (data[47] & 0x04):
            fields = struct.unpack('!26s4s4s2s', data[0:36])
            source_ip = socket.inet_ntoa(fields[1])
            source_port = int.from_bytes(fields[3], byteorder='big')
            machines[iface][source_ip]['tcp'][source_port] = 'other' 

async def tcp_syn_sender(sock, iface):
    for ip in machines[iface].keys():
        for port in range(65536):
            frame = build_tcp_syn_frame(
                iface,
                bytes.fromhex(machines[iface][ip]['mac'] .replace(':', '')),
                socket.inet_aton(ip),
                port.to_bytes(2, byteorder='big')
            )
            sock.send(frame)
            await asyncio.sleep(0)

async def tcp_syn_scan():
    sock = socket.socket(
        socket.AF_PACKET, 
        socket.SOCK_RAW,
        socket.htons(socket.ETHERTYPE_IP)
    )
    sock.setblocking(False)

    for iface in machines.keys():
        sock.bind((iface, 0))
        recv_task = asyncio.create_task(tcp_syn_receiver(sock, iface))
        print('[TCP SYN] Scanning ' + iface)

        await tcp_syn_sender(sock, iface)
        await asyncio.sleep(1) # poll for last packets
        
        recv_task.cancel()

    sock.close()

def tcp_connect_scan():
    for iface in machines.keys():
        print('[TCP CON] Scanning ' + iface)
        for ip, ip_data in machines[iface].items():
            for port in ip_data['tcp'].keys():
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    data = b''
                    result = sock.connect_ex((ip, port))
                    if not (result == 0):
                        sock.close()
                        continue

                    sock.send(b'echo\n')
                    try:
                        data = sock.recv(1024)
                    except:
                        pass
                    if b'ssh' in data.lower():
                        ip_data['tcp'][port] = 'ssh'
                    elif b'ftp' in data.lower():
                        ip_data['tcp'][port] = 'ftp'
                    elif b'0xFF' in data:
                        ip_data['tcp'][port] = 'telnet'
                    elif b'echo\n' == data:
                        ip_data['tcp'][port] = 'echo'
                    elif b'HTTP' in data:
                        ip_data['tcp'][port] = 'http' 
                    sock.close()

def local_scan():
    for iface in machines.keys():
        print('[SELF] Scanning ' + iface)
        host_ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        for port in range(65536):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host_ip, port))
                if result == 0:
                    machines[iface][host_ip]['tcp'][port] = 'other'
                    try:
                        data = sock.recv(1024)
                        print(data)
                    except:
                        pass

if __name__ == "__main__":
    asyncio.run(arp_scan())
    parse_arp_responses()
    
    asyncio.run(tcp_syn_scan())

    tcp_connect_scan()
    local_scan()

    results = {'routers': {}, 'machines': machines}

    with open('results.json', 'w') as json_file:
        json.dump(results, json_file, indent=4)

    print('Scan data written to results.json')

