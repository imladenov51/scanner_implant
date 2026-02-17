#!/usr/bin/env python3
# Scanner Implant - Ivan Mladenov

import asyncio
import json
import netifaces
import netaddr
import socket
import struct
import threading
import time

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

        machines[iface] = {}

        if netifaces.ifaddresses(iface)[netifaces.AF_INET]:
            device_inet = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
            device_link = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]
            
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
        data = await loop.sock_recv(sock, 256)
        arp_responses[iface].append(data)

async def arp_sender(sock, ips, iface):
    frame = build_arp_frame(iface)

    for ip in ips:
        new_frame = frame + socket.inet_aton(str(ip))
        # shitty fix for blocked socket
        try:
            sock.send(new_frame)
        except:
            # Blocked socket
            await asyncio.sleep(0.0001)
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
        print('\033[1m[ARP]\033[0m Scanning ' + iface)

        await arp_sender(sock, inet, iface)
        await asyncio.sleep(1) # poll for last packets

        recv_task.cancel()

    sock.close()

    parse_arp_responses()

def parse_arp_responses():
    for iface, packets in arp_responses.items():
        for packet in packets:
            fields = struct.unpack('!6s6s2s8s6s4s10s', packet[0:42])
            response_mac = fields[1].hex(':')
            response_ip = str(
                netaddr.IPAddress(int.from_bytes(fields[5], byteorder='big'))
            )

            machines[iface][response_ip] = {'mac': response_mac, 'tcp': {}}

def tcp_connect(iface, ip, start, end):
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.001)
            result = sock.connect_ex((ip, port))

            if (not result == 0) or (sock.getsockname() == sock.getpeername()):
                sock.close()
                continue

            data = b''
            sock.send(b'echo\r\n')
            try:
                data = sock.recv(256)
            except:
                pass
            machines[iface][ip]['tcp'][port] = service(data)
            sock.close()

def tcp_scan():
    for iface in machines.keys():
        print('\033[1m[TCP]\033[0m Scanning ' + iface + ' (spawned 4 threads)')
        for ip in machines[iface].keys():
            print('Checking open ports on ' + ip)
            threads = [
                threading.Thread(target=tcp_connect, args=(iface, ip, 0, 16384)),
                threading.Thread(target=tcp_connect, args=(iface, ip, 16384, 32768)),
                threading.Thread(target=tcp_connect, args=(iface, ip, 32768, 49152)),
                threading.Thread(target=tcp_connect, args=(iface, ip, 49152, 65536))
            ]
            
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

def service(data):
    if b'ssh' in data.lower():
        return 'ssh'
    elif b'ftp' in data.lower():
        return 'ftp' 
    elif b'\xFF' in data:
        return 'telnet' 
    elif b'echo\r\n' == data:
        return 'echo' 
    elif b'http' in data.lower():
        return 'http' 
    else:
        return 'other'

if __name__ == "__main__":
    start = time.time()
    asyncio.run(arp_scan())
    tcp_scan()
    end = time.time()

    results = {'routers': {}, 'machines': machines}

    with open('results.json', 'w') as json_file:
        json.dump(results, json_file, indent=4)

    print('Scan took ' + str(end - start) + ' seconds, data written to results.json')
