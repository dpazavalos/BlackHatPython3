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


# ICMP header decode, in C Types
class ICMP(ctypes.Structure):
    _fields_ = [
        ("type",            ctypes.c_ubyte),
        ("code",            ctypes.c_ubyte),
        ("checksum",        ctypes.c_short),
        ("unused",          ctypes.c_short),
        ("next_hop_mtu",    ctypes.c_short),
    ]

    def __new__(self, socket_buffer=None):
        """Form a given bytes string, copy against stored buffer fields to create our ICMP object"""
        # A given socket buffer arrives as a tuple. Extract bytes obj from [0]
        return self.from_buffer_copy(socket_buffer[0])

    def __init__(self, socket_buffer):
        pass


class ICMP_Decoder():
    """Simple sniffer with ICMP header decoder, intended to decypher dropped or refuced pings"""

    def __init__(self, listen_from: str=None):
        """


        Args:
            listen_from:
                Hostname IP to listen from; must be locally accessible
        """

        if not listen_from:
            listen_from = self.get_my_ip()
        self.host = listen_from

        self.windows_based = os.name == 'nt'

        # Set protocol to sniff (Windows is less discerning, allowing indiscriminate sniffing)
        if self.windows_based:
            self.socket_protocol = socket.IPPROTO_IP
        else:
            self.socket_protocol = socket.IPPROTO_ICMP

        # build sniffer socket
        self.sniffer = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW,
                                     proto=self.socket_protocol)

    @staticmethod
    def get_my_ip():
        """
        Quick socket build and destroy, to try and dig up a running IP. Tries to connect to google
        dns, and gets socket's IP from name

        Returns:
                Socket gathered IP
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            my_ip = sock.getsockname()[0]
            sock.close()
            return my_ip
        except OSError:
            raise OSError("Unable to determine running IP. Is this device connected?\n")

    def run(self):

        self.bind_sniffer()
        self.win_promisc_start()

        try:
            self.capture()
        except Exception as err:
            print(err)
        finally:
            self.win_promisc_end()

    def capture(self):
        """
        Contains the guts of our ping decoder. Captures packets, decyphers ICMP headers, displays
        ICMP message
        """

        while True:
            # Capture packet
            raw_buffer = self.sniffer.recvfrom(65565)
            # Extract IP header
            ip_header = IP(raw_buffer[:20])

            # Print detected protocol
            print(f"Protocol: {ip_header.protocol}")
            print(f"    {ip_header.src_address} -> {ip_header.dst_address}")

            if ip_header.protocol == 'ICMP':
                # Header offset
                offset = ip_header.ihl * 4
                # From offset to end of packet
                # todo this sizeof did not work. Maybe __sizeof__? Try when connected
                message = raw_buffer[offset:offset + ctypes.Structure.sizeof(ICMP)]
                message = raw_buffer[offset:offset + ICMP.__sizeof__()]
                # message = raw_buffer[offset:offset + len(ICMP)]
                # ICMP Class
                icmp_header = ICMP(message)

                print(f"    {icmp_header.type} {icmp_header.code}")

    def bind_sniffer(self):
        """Bind sniffer to host, set opt to include headers"""
        self.sniffer.bind((self.host, 0))
        self.sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def win_promisc_start(self):
        """
        Windows is less discerning on packets, but promiscuity must be manually triggered
        Enable promiscuous sniffing
        """
        if self.windows_based:
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def win_promisc_end(self):
        """
        Windows is less discerning on packets, but promiscuity must be manually triggered
        Disable promiscuous sniffing
        """
        if self.windows_based:
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


sniffer = ICMP_Decoder('localhost')
sniffer.run()
