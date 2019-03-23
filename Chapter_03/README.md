# Chapter 2 The Network

Chapter 3 delves into raw sockets and low level sniffing modules (Author's note: My networking 
degree comes in handy as heck here)

##### 01 UDP sniffer
Simple one-off packet sniffer. No modifications needed to convert to python3. 

##### 02 UDP sniffer, with IP decoder
Packet sniffer with IP header decoder. Successful implementation of ctypes.Structure with minimal
conversion needed. Added SSDP recognition
 
##### 03 ICMP Decoder
```
pip install netaddr
```
Incorporated ICMP header decoder, minor tweaks in ctypes.structures calling. 
To strengthen this port a few classful conversions were implemented; UDP sprayer is now standalone.
Additionally, enabled a self-detecting IP function to further utility and simplicity was implemented
in the primary logic. 
