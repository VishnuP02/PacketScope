#!/usr/bin/env python3
"""Writes sample.pcap: ordinary web/DNS/ping traffic, one ARP packet, and a SYN port scan.

Lets you try PacketScope without root or a live network:
    python3 tools/make_sample_pcap.py
    ./build/packetscope -r sample.pcap
"""
import socket
import struct

ETH_SRC = bytes.fromhex("bbbbbbbbbb02")
ETH_DST = bytes.fromhex("aaaaaaaaaa01")


def ether(ethertype, payload):
    return ETH_DST + ETH_SRC + struct.pack("!H", ethertype) + payload


def ipv4(proto, src, dst, l4):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + l4


def tcp(sport, dport, flags):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0)


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo():
    return struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"


SYN, ACK = 0x02, 0x10
packets = []
for i in range(6):  # a web session
    packets.append(ether(0x0800, ipv4(6, "192.168.1.10", "93.184.216.34", tcp(50000, 443, SYN if i == 0 else ACK))))
    packets.append(ether(0x0800, ipv4(6, "93.184.216.34", "192.168.1.10", tcp(443, 50000, SYN | ACK if i == 0 else ACK))))
for i in range(3):  # DNS lookups
    packets.append(ether(0x0800, ipv4(17, "192.168.1.10", "192.168.1.1", udp(40000 + i, 53, b"\x00" * 20))))
packets.append(ether(0x0800, ipv4(1, "192.168.1.10", "192.168.1.1", icmp_echo())))
packets.append(ether(0x0806, b"\x00" * 28))  # ARP
for port in range(20, 45):  # a SYN scan from one host
    packets.append(ether(0x0800, ipv4(6, "192.168.1.66", "192.168.1.10", tcp(54321, port, SYN))))

with open("sample.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, p in enumerate(packets):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)))
        f.write(p)
print(f"wrote sample.pcap with {len(packets)} packets")
