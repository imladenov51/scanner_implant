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
def build_arp_frame():
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

async def arp_receiver(sock, iface):
    loop = asyncio.get_running_loop()

    while True:
        data = await loop.sock_recv(sock, 4096)
        arp_responses[iface].append(data)

async def arp_sender(sock, ips):
    frame = build_arp_frame()

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

    # TODO: Spawn thread for each iface
    for iface, inet in inets.items():
        sock.bind((iface, 0))
        recv_task = asyncio.create_task(arp_receiver(sock, iface))
        print('[ARP] Scanning ' + iface)

        await arp_sender(sock, inet)
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

def build_tcp_syn_frame(iface, dest_mac, dest_ip, dest_port):
    host_mac: bytes = bytes.fromhex(
        netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
        .replace(':', '')
    )
    host_ip: bytes = socket.inet_aton(
        netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    )

    ip_sum = (
        int.from_bytes(host_ip[0:2], byteorder='big') +
        int.from_bytes(host_ip[2:4], byteorder='big') +
        int.from_bytes(dest_ip[0:2], byteorder='big') +
        int.from_bytes(dest_ip[2:4], byteorder='big')
    )

    ethernet_header  = dest_mac
    ethernet_header += host_mac
    ethernet_header += b'\x08\x00'

    ip_checksum = 0x4500 + 0x0028 + 0xabcd + 0x4006 + ip_sum
    while (ip_checksum > 0xffff):
        ip_checksum = (ip_checksum & 0xffff) + (ip_checksum >> 16)
    ip_checksum = 0xffff - ip_checksum
    ip_checksum = ip_checksum.to_bytes(2, byteorder='big')
    ip_header  = b'\x45\x00\x00\x28'
    ip_header += b'\xab\xcd\x00\x00'
    ip_header += b'\x40\x06'
    ip_header += ip_checksum
    ip_header += host_ip
    ip_header += dest_ip
    
    tcp_checksum = (
        0x0006 + ip_sum + 0x0014 + 0x3039 + 
        int.from_bytes(dest_port, byteorder='big') + 0x5002 + 0x7110
    )
    while (tcp_checksum > 0xffff):
        tcp_checksum = (tcp_checksum & 0xffff) + (tcp_checksum >> 16)
    tcp_checksum = 0xffff - tcp_checksum
    tcp_checksum = tcp_checksum.to_bytes(2, byteorder='big')
    tcp_header  = b'\x30\x39'
    tcp_header += dest_port
    tcp_header += b'\x00\x00\x00\x00'
    tcp_header += b'\x00\x00\x00\x00'
    tcp_header += b'\x50\x02\x71\x10'
    tcp_header += tcp_checksum
    tcp_header += b'\x00\x00'
    
    return ethernet_header + ip_header + tcp_header

async def tcp_syn_receiver(sock, iface):
    loop = asyncio.get_running_loop()

    while True:
        data = await loop.sock_recv(sock, 4096)
        if not (data[47] & 0x04):
            fields = struct.unpack('!26s4s4s2s', data[0:36])
            sender_ip = socket.inet_ntoa(fields[1])
            sender_port = int.from_bytes(fields[3], byteorder='big')
            machines[iface][sender_ip]['tcp'][sender_port] = 'TODO'

async def tcp_syn_sender(sock, iface):
    for ip, ip_data in machines[iface].items():
        for port in range(65536):
            dest_mac = bytes.fromhex(ip_data['MAC'].replace(':',''))
            dest_ip = socket.inet_aton(ip)
            dest_port = port.to_bytes(2, byteorder='big')
            frame = build_tcp_syn_frame(iface, dest_mac, dest_ip, dest_port)
            sock.send(frame)
            await asyncio.sleep(0) 

async def tcp_syn_scan():
    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(socket.ETHERTYPE_IP)
    )
    sock.setblocking(False)

    for iface in machines.keys():
        sock.bind((iface, 0))
        recv_task = asyncio.create_task(tcp_syn_receiver(sock, iface))
        print('[TCP SYN] Scanning ' + iface)

        await tcp_syn_sender(sock, iface)
        await asyncio.sleep(3) # poll for last packets

        recv_task.cancel()

    sock.close()

def tcp_connect_scan():
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )
    sock.settimeout(2.5)
    for iface in machines.keys():
        print('[TCP CON] Scanning ' + iface)
        for ip, ip_data in machines[iface].items():
            for port in ip_data['tcp'].keys():
                print('Trying ' + ip + ':' + str(port))
                sock.connect((ip, port))
                try:
                    data = sock.recv(1024)
                    if 'ssh' in data.lower():
                        ip_data['tcp'][port] = 'ssh'
                    elif 'ftp' in data.lower():
                        ip_data['tcp'][port] = 'ftp'
                except Exception as e:
                    # TODO: Send http request, etc.
                    pass
                ip_data['tcp'][port] = 'other'

    sock.close()
                 

if __name__ == "__main__":
    asyncio.run(arp_scan())
    
    parse_arp_responses()
   
    asyncio.run(tcp_syn_scan())

    tcp_connect_scan()
    
    results = {'routers': {}, 'machines': machines}
    print(json.dumps(results, indent=4))

