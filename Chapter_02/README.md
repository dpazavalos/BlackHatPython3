# Chapter 2 The Network

##### 01 TCP Client
Simple TCP Socket connect. Minimal change needed, mostly binary strings for socket

##### 02 UDP Client
Simple UDP Socket connect. Minimal change needed, mostly binary strings for socket

##### 03 TCP Server
Simple TCP listener and acceptor. Minimal changs, mostly binary strings for socket

##### 04 TCP Server
Python conversion of NetCat. More or less a complete overhaul in port. Classful conversion, 
additional options for clarity in file upload/execution, settable timeout, enforced explicit 
client/listening state flags, custom errors to enable safe client disconnect and remote server 
shutdown, funnel functions for consistency in sending, receiving, and string to binary conversion, 
behind the scenes work on loops and general logic (Original script was more of a quick cookbook)

Note: Ambitions demand me to partition this 500 line package into a proper module, but doing so 
exceeds scope and discards single file footprint. It is the author's desire to move on to the next 
module 

##### 05 TCP Proxy

