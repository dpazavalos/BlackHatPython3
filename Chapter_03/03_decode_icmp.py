import socket
import os
import struct
import ctypes
import time
import netaddr
import threading


#
# # # IP header decoder, in C type
#
class IP(ctypes.Structure):
    """C types interface, to decode ip header to parsable object. Returns object with attributes
    for each header field"""

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


#
# # # ICMP header decode, in C Types
#
class ICMP(ctypes.Structure):
    """C types interface, to decode icmp header to parsable object. Returns object with attributes
    for each header field"""

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
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


#
# # # ICMP Decoder
#
class ICMPDecoder:
    """Simple sniffer with ICMP header decoder, intended to decypher dropped or refuced pings"""

    def __init__(self, listen_from: str = None,):
        """
        Simple sniffer with ICMP header decoder, intended to decypher dropped or refuced pings


        Args:
            listen_from:
                Hostname IP to listen from; must be locally accessible
        """

        if not listen_from:
            listen_from = self._get_my_ip()
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
    def _get_my_ip():
        """
        Quick socket build and destroy, to try and dig up a running IP. Tries to connect to google
        dns, and gets socket's IP from socket name

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

    def capture(self):
        """
        Contains the guts of our ping decoder. Captures packets, deciphers ICMP headers, displays
        ICMP message
        """
        # Use a set to track unique finds
        host_up_set = set()

        while True:
            # Capture packet
            raw_buffer = self.sniffer.recvfrom(65565)
            # Extract IP header
            ip_header = IP(raw_buffer[:20])

            # Print detected protocol
            print_all = False
            if print_all:
                pass
                print(f"Protocol: {ip_header.protocol}")
                print(f"    {ip_header.src_address} -> {ip_header.dst_address}")

            if ip_header.protocol == 'ICMP':
                # Find Header offset, to gather only data contents
                offset = ip_header.ihl * 4
                message = raw_buffer[0][offset:offset + ctypes.sizeof(ICMP)]
                icmp_header = ICMP(message)

                if print_all:
                    print(f"    Type: {icmp_header.type}  Code: {icmp_header.code}")

                if icmp_header.type == icmp_header.code == 3:
                    host_up = f'    Host up: {ip_header.src_address}'
                    if host_up not in host_up_set:
                        print(host_up)
                        host_up_set.add(host_up)

    def win_promisc_end(self):
        """
        Windows is less discerning on packets, but promiscuity must be manually triggered
        Disable promiscuous sniffing
        """
        if self.windows_based:
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    def spray_udp_packets(self):
        """
        Call, build, and start a threaded UDP subnet sprayer. Sends out a simple UDP message to a
        wide variety of subnets. These subnets will respond in ICMP requests, which our sniffer
        listens for
        """
        sprayer = UDPSprayer()
        sprayer.run()
        print('spraying...')

    def run(self):
        """
        Primary logic. Binds sniffer, handles windows promiscuity mode (if applicable), calls a
        UDP sprayer, and listens for ICMP pings
        """

        self.bind_sniffer()

        self.win_promisc_start()

        self.spray_udp_packets()

        try:
            self.capture()
        except Exception as err:
            print(err)
        finally:
            self.win_promisc_end()


class UDPSprayer:
    """
    UDP sprayer object. Tries to connect to every IP in a subnet. Builds a simple socket, threads
    and tries to connect to all ip addresses in a given subnet
    """

    def __init__(self, subnet: str = None, spray_msg: bytes = None):
        """
        Args:
            subnet:
                subnet to try to connect to, use a netaddr usable string. Default 192.168.0.0/16
            spray_msg:
                Simple message to use when connecting. Can be specified, so responses can be
                precisely caught. Default
        """

        if not subnet:
            subnet = '192.168.0.0/16'
        self.subnet = subnet

        # message for UDP sprayer
        if not spray_msg:
            spray_msg = b"Don't mind me..."
        elif isinstance(spray_msg, str):
            spray_msg = spray_msg.encode()
        self.spray_msg = spray_msg

    def run(self):
        """
        Creates and starts a thread to spray UDPs in every indicated subnet. Sprayer includes a
        5 second delay, to allow listening a chance to begin
        """
        # print('Spraying')
        sprayer = threading.Thread(target=self._udp_sprayer)
        sprayer.start()

    def _udp_sprayer(self):
        """Actual UDP socket sprayer"""

        time.sleep(5)
        sender = socket.socket(type=socket.SOCK_DGRAM)

        for ip in netaddr.IPNetwork(self.subnet):
            try:
                sender.sendto(self.spray_msg, (str(ip), 65212))
            except Exception as err:
                print(err)


sniffer = ICMPDecoder()
sniffer.run()
