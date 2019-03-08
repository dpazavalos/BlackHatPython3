"""
Quick spool TCP server, using built in socket module
"""

import socket
import threading

bind_ip = '0.0.0.0'
bind_port = 9999

# Create client socket, using IPv4 and TCP socket type
server = socket.socket(family=socket.AF_INET,
                       type=socket.SOCK_STREAM)

server.bind((bind_ip, bind_port))
server.listen(5)


# Threadable client handler
def handle_client(client_socket: socket.socket):

    # Catch and print what client sent
    request = client_socket.recv(1024)
    print(f"    [*] Received\n")
    print(request.decode("utf-8"))

    # Respond with generic ACK
    client_socket.send(b"ACK!")
    client_socket.close()


print(f"[*] Listening on {bind_ip}:{bind_port}")
runs = 3
while runs != 0:

    client, addr = server.accept()
    print(f"  [*] Accepted connection from {addr[0]}:{addr[1]}")

    # Spin thread to handle incoming data
    client_handler = threading.Thread(target=handle_client, args=(client,))
    client_handler.start()

    runs -= 1

print("[*] Closed")
