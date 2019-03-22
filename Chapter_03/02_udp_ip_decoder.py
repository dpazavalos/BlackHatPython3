import socket
import os
import struct
import ctypes


# IP header decoder, in C type
class IP(ctypes.Structure):
    _fields_ = [
        ("ihl",             ctypes.c_ubyte, 4),
        ("version",         ctypes.c_ubyte, 4),
        ("tos",             ctypes.c_ubyte),
        ("len",             ctypes.c_short),
        ("id",              ctypes.c_short),
        ("offset",          ctypes.c_short),
        ("ttl",             ctypes.c_ubyte),
        ("protocol_num",    ctypes.c_ubyte),
        ("sum",             ctypes.c_short),
        ("src",             ctypes.c_ulong),
        ("dst",             ctypes.c_ulong),
    ]

    def __new__(self, socket_buffer=None):
        # A given socket buffer arrives as a tuple. Extract bytes obj from [0]
        return self.from_buffer_copy(socket_buffer[0])

    def __init__(self, socket_buffer):

        # Map constants and names
        self.protocol_map = {1: "ICMP", 2: "SSDP", 6: "TCP", 17: "UDP"}

        self.src_address = socket.inet_ntoa(struct.pack('<L', self.src))
        self.dst_address = socket.inet_ntoa(struct.pack('<L', self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except KeyError:
            self.protocol = str(self.protocol_num)


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

# Bind sniffer, Include IP headers
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Enable windows promiscuous mode
if windows_based:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:

        # Read packet
        raw_buffer = sniffer.recvfrom(65565)

        # Capture IP header
        ip_header = IP(raw_buffer[:20])

        # Print out detected protocol
        print(f"Protocol: {ip_header.protocol}")
        print(f"    {ip_header.src_address} -> {ip_header.dst_address}")


except Exception as err:
    print("Unknown error!")
    print(err)

except KeyboardInterrupt:
    # Ctrl-C Quit
    pass

finally:
    # disable windows promiscuous mode
    if windows_based:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
