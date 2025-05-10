from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dot11 import Dot11
import pandas as pd
from scapy.layers.inet6 import IPv6

def read_pcap(filename):
    with PcapReader(filename) as pcap:
        for packet in pcap:
            if Dot11 in packet:
                df = read_pcap_crypted(filename)
            else:
                df = read_pcap_decrypted(filename)
            return df

def read_pcap_crypted(filename):
    i = 0
    df = []
    for p in PcapReader(filename):
        df.append([])   
        df[i].extend([p.subtype, p.type, p.addr1, p.addr2, p.addr3, float(p.time), len(p)])
        i+=1
    df = pd.DataFrame(df, columns=["subtype", "type", "addr1", "addr2", "addr3", "time", "len"])

    return df

def read_pcap_decrypted(filename):
    df = []
    i = 0
    for packet in PcapReader(filename):
        df.append([])
        p = packet[Ether]
        df[i].extend([packet.type, len(packet), float(packet.time), p.src, p.dst])
        if IP in packet:
            df[i].extend([packet.proto, packet[IP].src, packet[IP].dst])
            if TCP in packet:
                df[i].extend([packet[TCP].sport, packet[TCP].dport])
            elif UDP in packet:
                df[i].extend([packet[UDP].sport, packet[UDP].dport])
        elif ARP in packet:
            df[i].extend([None, packet.psrc, packet.pdst])
        else:
            if packet.type == 34525:
                df[i].extend([None, packet[IPv6].src, packet[IPv6].dst])
                if UDP in packet:
                    df[i].extend([packet[UDP].sport, packet[UDP].dport])
                elif TCP in packet:
                    df[i].extend([packet[TCP].sport, packet[TCP].dport])
        i+=1
    df = pd.DataFrame(df, columns=["type", "len", "time", "src", "dst", "proto", "ip_src", "ip_dst", "ip_src_port", "ip_dst_port"])

    return df

