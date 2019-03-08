"""
Quick spool UDP client, using built in socket module
"""

import socket

# target_host = "www.google.com"
target_host = "127.0.0.1"
target_port = 80

# Create client socket, using IPv4 and UPD socket type
client = socket.socket(family=socket.AF_INET,
                       type=socket.SOCK_DGRAM)

# Send junk data
client.sendto(b"AAAAAAAAAAAA", (target_host,target_port))

# Catch data
data, addr = client.recvfrom(4096)

# Fails without 04_udp_server running
print(data)
