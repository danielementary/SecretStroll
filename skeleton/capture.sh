#!/bin/bash
for i in {1..100}
  do
    echo i
    echo $i
    tcpdump -i lo 'port 9050' -w data/$i\_$1.pcap &
    sleep 0.1
    python3 client.py grid -p key-client.pub -c attr.cred -r 'a' -t $i > /dev/null
    sleep 1
    kill "$!"                      # kill the background process
  done