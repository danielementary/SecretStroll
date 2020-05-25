# Part 3
The part 3 uses captured traffic between the server and the client. To setup this capture, the server must be running and the client must be registered and in possession of the server's public key and his anonymous credentials.

### capture.sh
This bash script will capture the traffic between the client and the server.  
It must be run in the client docker, with a running server. The server's public key must be named `key-client.pub` and the anonymous credentials `attr.cred`.  
It takes one command line argument, the suffix of the files that will generated.

A run with the following command :
```
./capture.sh 3
```
will generate 100 files in a folder `data` name `1_3.pcap` up to `100_3.pcap` containing the captured traffic for the given cell.

### pcap.py
This file requires the scapy package, which can be installed with `pip3 install scapy`.  

`pcap.py` contains various utility functions and can be used as follows:

```
python3 pcap.py filter
```
* Run the `filter()` function which checks and outputs the name of all files in the `data` directory that are incomplete capture files.  
Note that this call will fail if a non capture file is found. (MacOS users : delete .DS_Store).  


```
python3 pcap.py save
```
* Run the `save()` function which parses all catpure files in the `data` directory and extract informations for the classifier in a `packets_lens.csv` file.  
Note that this call will fail if a non capture file is found. (MacOS users : delete .DS_Store). 


### classifier.py

This file contains the classifier for the network fingerprinting attack. It requires the pytorch package, which can be installed with `pip3 install torch`.  
It require the `pcap.py` file as well as the data formatted in a `packets_lens.csv` file. The data can be formatted and saved using the `save` argument for `pcap.py`.
It can be run without argument as follows:
```
python3 classifier.py
```


## Sample run
Setup the client and server : 
```
(server) $ python3 server.py gen-ca -a 'attributes' -s key.sec -p key.pub
(server) $ python3 server.py run -s key.sec -p key.pub
```
```
(client) $ python3 client.py get-pk -o key-client.pub
(client) $ python3 client.py register -a 'attributes' -p key-client.pub -u your_name -o attr.cred
```

Run the capture with : 
```
(client) $ ./capture.sh 1
(client) $ ./capture.sh 2
(client) $ ./capture.sh 3
(client) $ ./capture.sh 4
(client) $ ./capture.sh 5
(client) $ ./capture.sh 6
(client) $ ./capture.sh 7
(client) $ ./capture.sh 8
(client) $ ./capture.sh 9
(client) $ ./capture.sh 10
```
WARNING : The catpure takes a really long time to complete (like almost a day). Remove the correct data from the `data` folder before testing this, to avoid overwriting the existing data.  
  
Check the capture files and rerun the capture for the necessary files: 
```
$ python3 pcap.py filter
```

Preprocess and save the data for the classifier :
```
$ python3 pcap.py save
```

Run the classifier:
```
$ python3 classifier.py
```