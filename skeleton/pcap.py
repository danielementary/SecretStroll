from scapy.all import *
from pcaper import PcapParser
import sys
import os
import re




def filter(remove):
    #None to account cell number from 1 to 100
    nb_poi = [None, 11, 14, 13, 5, 11, 6, 10, 12, 8, 5, 12, 9, 12, 9, 14, 11, 15, 10, 10, 7, 6, 10, 9, 10, 15, 13, 8, 8, 12, 8, 11, 8, 7, 9, 7, 15, 11, 12, 11, 3, 15, 7, 8, 14, 12, 10, 11, 6, 7, 8, 14, 9, 9, 5, 9, 11, 13, 10, 7, 12, 12, 11, 8, 15, 10, 11, 8, 6, 13, 12, 9, 6, 14, 13, 11, 4, 14, 9, 9, 10, 10, 17, 13, 16, 3, 11, 9, 15, 6, 5, 8, 10, 6, 7, 8, 12, 14, 5, 13, 13]

    pcap_parser = PcapParser()
    for file in os.listdir("data"):
        params = {
            'input': 'data/'+file,
        }
        nb = 0
        cell_id = 0
        #print("Processing File: " + file)
        for request in pcap_parser.read_pcap(params):
            if cell_id == 0:
                cell_id = int(re.search(r'\d+',request.origin).group())
            else:
                nb += 1
        if nb_poi[cell_id] != nb:
            print(file)
            if remove:
                os.remove("data/"+file)


def aggregate():
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
    return datas

if __name__ == "__main__":
    if sys.argv[1] == "filter":
        try:
            if sys.argv[2] == "remove":
                filter(True)
            else:
                filter(False)
        except Exception:
            filter(False)
    elif sys.argv[1] == "aggregate":
        aggregate()
    else:
        print("unrecognized command!")
    
    