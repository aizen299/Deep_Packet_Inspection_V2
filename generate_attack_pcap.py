from scapy.all import *
import random

packets = []

# TCP burst
for i in range(1500):
    pkt = Ether() / \
          IP(src=f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
             dst=f"192.168.1.{random.randint(1,254)}") / \
          TCP(sport=random.randint(1024,65535),
              dport=random.choice([80,443,8080,8443]),
              flags="S") / \
          Raw(load="X"*random.randint(20,200))
    packets.append(pkt)

# Malformed UDP
for i in range(100):
    pkt = Ether() / \
          IP(dst="8.8.8.8") / \
          UDP(dport=53) / \
          Raw(load=b"\x00\xff\x00\xff\x00")
    packets.append(pkt)

# Unknown traffic
for i in range(500):
    pkt = Ether() / \
          IP(dst=f"172.16.{random.randint(0,5)}.{random.randint(1,254)}") / \
          TCP(dport=random.randint(1000,9000)) / \
          Raw(load="UNKNOWN_PAYLOAD")
    packets.append(pkt)

wrpcap("extreme_traffic.pcap", packets)
print("Generated extreme_traffic.pcap")