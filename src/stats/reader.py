from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dot11 import Dot11
import pandas as pd
from scapy.layers.inet6 import IPv6

from .statistic import subtype_crypted, types_crypted, protocol_names

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
        subtype = p.subtype
        ptype = p.type
        if not ptype is None:
            ptype = types_crypted[int(ptype)]
            if subtype:
                subtype = subtype_crypted[int(p.type)][subtype]
        df[i].extend([subtype, ptype, p.addr1, p.addr2, p.addr3, float(p.time), len(p)])
        i+=1
        # if i>50000:
        #     break

    df = pd.DataFrame(df, columns=["subtype", "type", "addr1", "addr2", "addr3", "time", "len"])

    return df

def read_pcap_decrypted(filename):
    df = []
    i = 0
    for packet in PcapReader(filename):
        df.append([])
        p = packet[Ether]
        ptype = packet.type
        if ptype:
            ptype = protocol_names[int(packet.type)]
        df[i].extend([ptype, len(packet), float(packet.time), p.src, p.dst])
        if IP in packet:
            proto = packet.proto
            if proto:
                proto = protocol_names[packet.proto]
            df[i].extend([proto, packet[IP].src, packet[IP].dst])
            if TCP in packet:
                psport = packet[TCP].sport
                if psport:
                    psport = str(int(psport))
                pdport = packet[TCP].dport
                if pdport:
                    pdport = str(int(pdport))
                df[i].extend([psport, pdport])
            elif UDP in packet:
                psport = packet[UDP].sport
                if psport:
                    psport = str(int(psport))
                pdport = packet[UDP].dport
                if pdport:
                    pdport = str(int(pdport))
                df[i].extend([psport, pdport])
        elif ARP in packet:
            df[i].extend([None, packet.psrc, packet.pdst])
        else:
            if ptype == protocol_names[34525]:
                df[i].extend([None, packet[IPv6].src, packet[IPv6].dst])
                if UDP in packet:
                    psport = packet[UDP].sport
                    if psport:
                        psport = str(int(psport))
                    pdport = packet[UDP].dport
                    if pdport:
                        pdport = str(int(pdport))
                    df[i].extend([psport, pdport])
                elif TCP in packet:
                    psport = packet[TCP].sport
                    if psport:
                        psport = str(int(psport))
                    pdport = packet[TCP].dport
                    if pdport:
                        pdport = str(int(pdport))
                    df[i].extend([psport, pdport])
        i+=1
        # if i>500:
        #     break
    df = pd.DataFrame(df, columns=["type", "len", "time", "src", "dst", "proto", "ip_src", "ip_dst", "ip_src_port", "ip_dst_port"])

    return df

