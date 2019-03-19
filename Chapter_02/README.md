# Chapter 2 The Network

Chapter 2 is mostly an introduction to low level tools, creating pure python client/server tools.

##### 01 TCP Client
Simple TCP Socket connect. Minimal change needed, mostly binary strings for socket

##### 02 UDP Client
Simple UDP Socket connect. Minimal change needed, mostly binary strings for socket

##### 03 TCP Server
Simple TCP listener and acceptor. Minimal changs, mostly binary strings for socket

##### 04 Netcat
Python conversion of NetCat. More or less a complete overhaul in port
 - Classful conversion
 - additional options and args for clarity in file upload/execution 
 - enforced explicit Server/Client state flags
 - custom errors to enable safe client disconnect and remote server shutdown, 
 - funnel functions for consistency in sending, receiving, and string to binary conversion, 
 - behind the scenes work on loops and general logic (Original script was more of a quick cookbook)

Note: Ambitions demand me to partition this 500 line package into a proper module, but doing so 
exceeds scope and discards single file footprint. It is the author's desire to move on to the next 
module 

##### 05 TCP Proxy
Basic foundation for a TCP proxy
 - Rewrote hexdump function to take advantage of 3's codecs libraries.
 - Implemented deliteralizer function to ensure string literals are hexdumped, but stdout normally 
 - Imported static send/receive data funnel functions from previous module, enforced args (Because 
 constant incremental improvements are life) 

##### 06 SSH With Paramiko
```
pip install paramiko
```
Basic SSH command sender, using SSHv2 API Paramiko.
 - Of note is the reusability of our centralized send/receive data functions implemented in 04 with 
a paramiko ssh session (from client.get_transport().open_session()).

##### 07 Custom SSH client/server
Enhanced implementation of 04 Netcat object, using Paramiko API, while also offering a chance for
some revisions to the underlying structure. 
 - Ported helper functions into separate class.
 - Ported all class attributes into dataclass-like, with incorporated getopt parsing for standalone 
functionality
 - Split Server and Client functions into child classes
 
Note: as of this writing (2019-03-19) Paramiko is relying on depreciated crypto objects. While a
working unofficial patch exists (https://gist.github.com/vkobel/52d795920aacd74afb4db15a89c39b8b) 
merging this patch exclusively for this project is a rabbit hole I'm not looking to go down. Will
pick up on a new release 
  
##### 08 SSH Tunneling
2019-03-19 On hold until Paramiko patches
