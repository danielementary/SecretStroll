from scapy.all import *
import sys
import os
import re


def filter2(remove):
    #None to account cell number from 1 to 100
    nb_poi = [None, 11, 14, 13, 5, 11, 6, 10, 12, 8, 5, 12, 9, 12, 9, 14, 11, 15, 10, 10, 7, 6, 10, 9, 10, 15, 13, 8, 8, 12, 8, 11, 8, 7, 9, 7, 15, 11, 12, 11, 3, 15, 7, 8, 14, 12, 10, 11, 6, 7, 8, 14, 9, 9, 5, 9, 11, 13, 10, 7, 12, 12, 11, 8, 15, 10, 11, 8, 6, 13, 12, 9, 6, 14, 13, 11, 4, 14, 9, 9, 10, 10, 17, 13, 16, 3, 11, 9, 15, 6, 5, 8, 10, 6, 7, 8, 12, 14, 5, 13, 13]

    nb_file = 0
    for file in os.listdir("data"):
    #file ="9_7.pcap"
        nb = 0
        cell_id = 0
        #print("Processing File: " + file)
        packets = rdpcap("data/"+file)
        for pkt in packets:
            if pkt[TCP].payload:
                i = pkt[TCP].load.decode('utf-8').find("cell_id=")
                if i != -1:
                    cell_id = re.search(r'\d+',pkt[TCP].load.decode('utf-8')[i:]).group()
                    break
        for pkt in packets:
            if pkt[TCP].payload:
                if "HTTP/1.0 200 OK" in pkt[TCP].load.decode('utf-8'):
                    nb += 1
        #print(nb)
        if nb_poi[int(cell_id)] +1 != nb:
            print(file)
            nb_file += 1
            if remove:
                os.remove("data/"+file)

    print(nb_file)


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
                filter2(True)
            else:
                filter2(False)
        except Exception:
            filter2(False)
    elif sys.argv[1] == "aggregate":
        aggregate()
    else:
        print("unrecognized command!")
    
    