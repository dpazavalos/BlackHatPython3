"""
Misc functions cultivated across the chapter. Ported here for posterity, but'll keep on working
them into later packages
"""

import socket
from typing import Union, List
class Helpers:
    """Static functions, to use as helpers"""

    @staticmethod
    def send_data(to_socket: socket.socket, data_stream: bytes,
                  send_timeout=2) -> None:
        """
        Centralised function to handle sending data stream to receive data. Sends data in consistent
        buffer sizes

        Args:
            to_socket:
                Socket to send stream to
            data_stream:
                Data stream to send
            send_timeout:
                Set timeout for to_socket
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
    def receive_data(from_socket: socket.socket,
                     from_timeout=2) -> bytes:
        """
        Centralised fuction to handle receiving one or more packet buffers from TCP socket
        Args:
            from_socket:
                Socket sending stream to this instance.
            from_timeout:
                Set timeout for from_socket
        Returns:
                Complete binary stream from socket
        """
        from_socket.settimeout(from_timeout)
        fragments: List[bytes] = []
        try:
            stream = from_socket.recv(4096)
            fragments.append(stream)
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
            to_display:
                Item/s to join together. Either bytes or regular strings
            end:
                default print end arg
        """
        for item in to_display:
            try:
                print(item.decode(), end=end)
            except AttributeError:
                print(item, end=end)


import sys
import getopt
class OptionsSetter:
    """
    A Dataclass-like template, centralized storage for parsing startup arguments for a module.
    Carries defaults, uses getopt to set desired arguments
    """
    # Define variables, with defaults

    x: bool = False
    y: str = ''
    z: bool = False

    @staticmethod
    def usage():
        """
        Choose one:
        Module docstring doubles as --help
        Stores Module docstring locally
        """
        print(__doc__)
        exit()

    # Parse args, overwrite to create running attributes
    def __init__(self):
        if __name__ == '__main__' and len(sys.argv) == 1:
            self.usage()

        try:
            opts, args = getopt.getopt(sys.argv[1:], "hxy:z",
                                       ['help', 'exe', 'why=', 'zee'])

            for opt, arg in opts:

                if opt in ('-h', '--help'):
                    self.usage()

                elif opt in ('x', 'exe'):
                    self.__setattr__('x', True)

                elif opt in ('y', 'why'):
                    self.__setattr__('y', arg)

                elif opt in ('z', 'zee'):
                    self.__setattr__('z', True)

                elif not any((self.x, self.z)):
                    raise SyntaxError("Must explicitly state x or y!")

                elif all((self.x, self.z)):
                    raise SyntaxError("Cannot run both x AND y!")

                else:
                    raise SyntaxError(f"Unhandled option: {opt}")

        except (getopt.GetoptError, SyntaxError) as err:
            print(err)
            self.usage()

        except Exception as err:
            print('Unknown error, \n', err)
            self.usage()
