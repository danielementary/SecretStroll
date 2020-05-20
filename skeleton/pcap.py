from scapy.all import *
import os
import re

datas = {}

for n in range(1,101):
    datas[str(n)] = []

for file in os.listdir("data"):
    packets = rdpcap("data/"+file)
    for pkt in packets:

        if pkt[TCP].payload:
            i = pkt[TCP].load.decode('utf-8').find("cell_id=")
            if i != -1:
                cell_id = re.search(r'\d+',pkt[TCP].load.decode('utf-8')[i:]).group()
                break
        
    for pkt in packets:
        pkt[TCP].remove_payload()
        datas[cell_id] += [raw(pkt)]
    