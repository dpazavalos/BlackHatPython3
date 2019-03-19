import socket
import os

# Host to listen to
host = "192.168.1.101"
windows_based = os.name == 'nt'


# Windows is less discerning on packets, allowing indiscriminate protocol sniffing
if windows_based:
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

# Build sniffer, raw sockets
sniffer = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket_protocol)

# Bind sniffer
sniffer.bind((host, 0))

# Include IP headers
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Enable windows promiscuous mode
if windows_based:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

response = sniffer.recvfrom(65565)
print(response[0])

if windows_based:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
