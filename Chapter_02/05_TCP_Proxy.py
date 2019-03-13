"""
Python TCP proxy. Listens, catches, and forwards data to a designated remote address
"""

import sys
import socket
import threading
from textwrap import dedent
from typing import List
from typing import Union
import codecs
from collections import namedtuple


class Proxy:

    def __init__(self, *,
                 loc_host: str = "127.0.0.1", loc_port: int = 9999,
                 rem_host: str = None, rem_port: int = None,
                 receive_first: bool = False):
        """
        Args:
            loc_host: Host IP to listen and run proxy on
            loc_port: Host port to listen and run proxy on
            rem_host: Remote Host IP to send data on
            rem_port: Remote Port to send data to
            receive_first: Indicate if proxy must first request data before entering main loop
                (typically a banner or other header type of data)
        """

        # Defaults as foundation
        self.loc_host: str = loc_host
        """Host IP to listen and run proxy on"""
        self.loc_port: int = loc_port
        """Host port to listen and run proxy on"""
        self.rem_host: str = rem_host
        """Remote Host IP to send data on"""
        self.rem_port: int = rem_port
        """Remote Port to send data to"""
        self.receive_banner: bool = receive_first
        """Indicate if proxy must first request data before entering main loop
        (Typically banner data, or similar)"""

        self.verbose = True
        """Verbosity"""

        try:
            self.arg_parser()
        except SyntaxError:
            self.usage()

    def arg_parser(self):
        """
        Parse sys.argvs to assign variables
        """
        try:
            self.loc_host = sys.argv[1]
            self.loc_port = int(sys.argv[2])
            self.rem_host = sys.argv[3]
            self.rem_port = int(sys.argv[4])
            self.receive_banner = sys.argv[5] == "True"
        except (IndexError, ValueError):
            raise SyntaxError

    def usage(self):
        """
        Prints on Screen usage, closes script
        """
        print(dedent("""
        TCP Proxy
        
        ./05_TCP_Proxy.py [localhost: str] [localport: int] 
                          [remotehost: str] [remoteport: int] 
                          [receive_first: bool] 
        
        example: ./05_TCP_Proxy.py 127.0.0.1 9999 172.16.0.5 80 True
        """))
        exit()

    def server_loop(self):

        # spool server to listening target address
        server = socket.socket()
        # Try starting listening server
        try:
            server.bind((self.loc_host, self.loc_port))
        except Exception as err:
            self.verprint(
                f"[x] ! Unexpected error while starting server on {self.loc_host}:{self.loc_port} ! ")
            self.verprint(err)
            exit()

        self.verprint(f"[*] Listening on {self.loc_host}:{self.loc_port}")
        server.listen(5)

        while True:
            # Loop broken by explicit error or cmd
            client_socket, addr = server.accept()

            proxy_thread = threading.Thread(target=self.proxy_handler,
                                            args=(client_socket, addr))

            proxy_thread.start()

    def proxy_handler(self, client_socket: socket.socket, addr: str):
        """

        """
        self.verprint(f'--[*] Accepted connection from {addr[0]}:{addr[1]}')
        remote_socket = socket.socket()

        # Try connecting to remote address
        try:
            remote_socket.connect((self.rem_host, self.rem_port))
            self.verprint(f'--[*] Forwarding to {self.rem_host}:{self.rem_port}')
        except Exception as err:
            self.verprint(
                f"--[x] ! Unexpected error while binding to {self.rem_host}:{self.rem_port} ! ")
            self.verprint(err)

        # Banner data

        if self.receive_banner:
            self.verprint("[<--] Receiving initial data from remote end")
            remote_buffer = self.receive_data(from_socket=remote_socket)
            self.verprint(self.hexdump(remote_buffer).decode())

            remote_buffer = self.response_handler(remote_buffer)

            if len(remote_buffer):
                print(f"[-->] Sending {len(remote_buffer)} bytes to localhost")
                self.send_data(to_socket=client_socket, data_stream=remote_buffer)

        # Begin main loop
        # Read from local, send to remote, repeat

        while True:
            # broken by explicit errors

            #
            local_buffer = self.receive_data(from_socket=client_socket)

            if len(local_buffer):
                self.verprint(f"[<--] Received {len(local_buffer)} bytes from localhost")
                self.verprint(self.hexdump(local_buffer).decode())

                # handle request
                local_buffer = self.request_handler(local_buffer)

                self.send_data(to_socket=remote_socket, data_stream=local_buffer)
                self.verprint("[-->] Sent to remote host")

                remote_buffer = self.receive_data(from_socket=remote_socket)
                if len(remote_buffer):
                    self.verprint(f"[<--] Received {len(remote_buffer)} from remote")
                    self.verprint(self.hexdump(remote_buffer).decode())

                    remote_buffer = self.response_handler(remote_buffer)
                    self.send_data(to_socket=client_socket, data_stream=remote_buffer)

                    self.verprint("[-->] Sent to localhost")

            if not len(local_buffer) or len(remote_buffer):
                client_socket.close()
                remote_socket.close()
                self.verprint("No more data. Closing")
                break


    # # #

    # # # Shared Functions

    # # #

    def request_handler(self, buffer):
        """
        Generic packet request handler and modifier
        Returns:
             data stream, intended to be sent to remote host
        """
        return buffer

    def response_handler(self, buffer):
        """
        Generic packet reponse handler and modifier
                Returns:
             data stream, intended to be sent to local host
        """
        return buffer

    @staticmethod
    def send_data(*, to_socket: socket.socket, data_stream: bytes,
                  send_timeout=2) -> None:
        """
        Centralised function to handle sending data stream to receive data. Sends data in consistent
        buffer sizes
        Args:
            to_socket: Socket to send stream to
            data_stream: Data stream to send
        """
        to_socket.settimeout(send_timeout)
        try:
            data_fragments = []
            for i in range(0, len(data_stream), 4096):
                # Break data stream into byte sized bites
                data_fragments.append(data_stream[i:i + 4096])
            if data_fragments[-1] == 4096:
                # Make sure last fragment isn't BUFFER bytes long
                data_fragments.append(b'\n')
            for frag in data_fragments:
                to_socket.send(frag)
        except TimeoutError:
            pass

    @staticmethod
    def receive_data(*, from_socket: socket.socket,
                     recv_timeout=2) -> bytes:
        """
        Centralised fuction to handle receiving one or more packet buffers from TCP socket
        Args:
            from_socket: Socket sending stream to this instance.
        Returns:
              Complete binary stream from socket
        """
        from_socket.settimeout(recv_timeout)
        try:
            stream = from_socket.recv(4096)
            fragments: List[bytes] = [stream]
            while True:
                if len(stream) < 4096:
                    break
                else:
                    stream = from_socket.recv(4096)
                    fragments.append(stream)
        except TimeoutError:
            pass
        return b''.join(fragments)

    @staticmethod
    def deliteral(delit_string: str):
        """
        Function to deliteralize common string literals in a string (aka '\\\\n' to '\\\\\\\\n')

        Args:
            delit_string:
                A string to delit
        Returns:
             Copy of string given
        """
        string_list = list(delit_string)
        # Mem ID should be consistent across runs, but class and modularlize in future uses
        Literal = namedtuple('Literal', ['old', 'new'])
        literals = (
            Literal('\r', '\\r'),
            Literal('\t', '\\t'),
            Literal('\n', '\\n'),
            Literal('\b', '\\b'),
            Literal('\a', '\\a'),
            Literal("\'", "\\'"),
            Literal('\"', '\\"')
        )
        for ndx, char in enumerate(string_list):
            for lit in literals:
                if char == lit.old:
                    string_list[ndx] = lit.new
        return ''.join(string_list)

    def hexdump(self, to_dump: Union[bytes, str], length=8):
        """
        Given a string or bytestring, create an on screen display of hex values,
        length characters long
        Args:
            to_dump:
                String or bytes array to find hex values of
            length:
                # of characters to show per line
        Returns:
                binary string of hex values with their original values, to be printed on screen
        """
        results = []  # Final output array, to be joined when returning

        # Type acceptance
        if isinstance(to_dump, bytes):
            chars = to_dump.decode()
        elif isinstance(to_dump, str):
            chars = to_dump
        else:
            raise SyntaxError("Why did you try to hexdump something that's neither str nor bytes")

        for i in range(0, len(chars), length):
            line = []  # Array to hold this line
            step = chars[i:i + length]  # step through string, length char long

            # Encode each str char into it's hex value (bytes)
            hex_list = [codecs.encode(char.encode(), 'hex') for char in list(step)]

            # Deliteralize any nested string literals for consistent display
            # this is done after hexing; in hex '\n' != '\\n'
            # Replace
            step = self.deliteral(step)

            # Gap final row with any needed blank spaces
            if len(hex_list) < length:
                for x in range(length - len(hex_list) - 1):
                    hex_list.append(b'   ')

            # Join line items together, and then into results array
            line.append(b' '.join(hex_ for hex_ in hex_list))
            line.append(b'    ')
            line.append(step.encode())
            results.append(b' '.join(item for item in line))
        return b'\r\n'.join(results)

    @staticmethod
    def bin_join(*to_join: Union[str, bytes]) -> bytes:
        """
        Funnel function to reliably concatenate binary and strings into binaries. Can also be used
        to ensure a single item is bytes string

        Args:
            to_join: Item/s to join together. Either bytes or regular strings
        Return:
            Properly concatenated bytes string
        """
        binary_bytes = []
        for item in to_join:
            if not item:
                pass
            elif isinstance(item, int):
                binary_bytes.append(str(item).encode())
            elif isinstance(item, str):
                binary_bytes.append(item.encode())
            else:
                binary_bytes.append(item)
        return b''.join(binary_bytes)

    @staticmethod
    def bin_print(*to_display, end='\n'):
        """
        Funnel function to reliably print binary or regular strings.

        Args:
            to_display: Item/s to join together. Either bytes or regular strings

            end: default print end arg

        """
        for item in to_display:
            try:
                print(item.decode(), end=end)
            except AttributeError:
                print(item, end=end)

    def verprint(self, *to_print) -> None:
        """
        Default check against verbosity attribute, to see if allowed to print

        Args:
            *to_print: emulation of print *args. pass as normal
        """
        if self.verbose:
            for item in to_print:
                self.bin_print(item, end=' ')
            print()

    def run(self):
        self.server_loop()

if __name__ == '__main__':
    proxy = Proxy()
    proxy.run()
