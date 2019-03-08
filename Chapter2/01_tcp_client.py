"""
Quick spool TCP client, using built in socket module
"""

import socket

target_host = "info.cern.ch"
target_port = 80

# Create client socket, using IPv4 and TCP socket type
client = socket.socket(family=socket.AF_INET,
                       type=socket.SOCK_STREAM)

# Connect client socket to global targets
client.connect((target_host, target_port))

# Send basic get request
client.send(b"GET /hypertext/WWW/TheProject.html HTTP/1.0\r\nHost: info.cern.ch\r\n\r\n")

# Catch anticipated respose
response = client.recv(4098)

print(response.decode("utf-8"))
