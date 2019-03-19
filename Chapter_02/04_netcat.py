"""
Limited python recreation of GNU Netcat tool. Allows for remote file upload and execution, and
non-interactive shell commands (single line commands, no true interactivty)

Netcat (often abbreviated to nc) is a computer networking utility for reading from and writing to
network connections using TCP or UDP. Netcat is designed to be a dependable back-end that can be
used directly or easily driven by other programs and scripts.

See README, or --help string for more details
"""

import sys
import socket
import getopt
import threading
import subprocess
from textwrap import dedent
from typing import Union, Tuple, List


class ShutdownListen(socket.error):
    """Custom error used to shutdown listening server"""


class CloseConnection(socket.error):
    """Custom error used to safely disconnect connecting client"""


class NC:
    """
    Limited python recreation of GNU Netcat tool
    """

    def __init__(self, *,
                 target='localhost', port=9999,
                 connecting=False, upload=None, initial_cmd=None,
                 listening=False, write_to=None, execute=None, shell=False, verbose=False,
                 close_connection='bhpquit', shutdown_listening='bhpshutdown', timeout=60):
        """
        Limited python recreation of GNU Netcat tool. Can be imported and init, or run from command
        line. See Readme for more information
        """

        self.target = target
        """Target IP"""
        self.port = port
        """Target port"""

        # Connecting functions
        self.connecting = connecting
        """Connect to listening server on [host]:[port]"""
        self.upload = upload
        """File to upload to listening server"""
        self.initial_cmd = initial_cmd

        # Listening functions
        self.listening = listening
        """Listen on [host]:[port] for incoming connections"""
        self.write_to = write_to
        """If a client sends a file, write to this destination"""
        self.execute = execute
        """When a client connects, listener will execute this file"""
        self.shell = shell
        """Initialize a shell loop, to run one-off commands by connecting clients"""

        self.verbose = verbose
        """Enable on screen verbosity"""

        self.close_connection = close_connection
        """Specific command to disconnect connected client"""
        self.shutdown_listening = shutdown_listening
        """Specific command to shutdown listening script"""
        self.listening_active = True
        """"""
        self.timeout = timeout

        if __name__ == '__main__' and len(sys.argv) == 1:
            self.usage()

        try:
            opts, args = getopt.getopt(sys.argv[1:], "ht:p:cu:i:lw:e:sv",
                                       ['help', 'target=', 'port=', 'timeout=',
                                        'connect', 'upload=', '--initial=',
                                        'listen', 'write=', 'execute=', 'shell', 'verbose'])
            for opt, arg in opts:
                if opt in ('-h', '--help'):
                    self.usage()

                elif opt in ('-t', '--target'):
                    self.target = arg

                elif opt in ('-p', '--port'):
                    self.port = int(arg)

                elif opt == '--timeout':
                    self.timeout = int(arg)

                elif opt in ('-c', '--connecting'):
                    self.connecting = True

                elif opt in ('-u', '--upload'):
                    self.upload = arg

                elif opt in ('-i', '--initial'):
                    self.initial_cmd = arg

                elif opt in ('-l', '--listen'):
                    self.listening = True

                elif opt in ('-w', '--write'):
                    self.write_to = arg

                elif opt in ('-e', '--execute'):
                    self.execute = arg

                elif opt in ('-s', '--shell'):
                    self.shell = True

                elif opt in ('-v', '--verbose'):
                    self.verbose = True

                elif not self.target or not self.port:
                    raise SyntaxError("Must explicitly state target IP and Port!")

                elif True not in [not self.connecting or not self.listening]:
                    input((not self.connecting or not self.listening))
                    raise SyntaxError("Must explicitly state connecting or listening function!")

                else:
                    raise SyntaxError(f"Unhandled option: {opt}")

        except (getopt.GetoptError, SyntaxError) as err:
            print(err)
            self.usage()

    @staticmethod
    def usage():
        """Default usage screen. Calls exit(0)"""
        print(dedent("""
        BHP Net Tool (Updated for Python3)
        
        Usage: bhpnet.py -t target_host -p port

        -h --help                 - Show this help page
        
        -t -target                - Target IP   (Default: Localhost)
        -p -port                  - Target Port (Default: 9999)

        -c --connect              - Run as a connecting client, to send commands 
                                    or files to a listening server
        -i --initial=cmd_to_run   - (Connecting) Connect with an initial command. 
                                    Note that a listening server writes and executes 
                                    files before running any command
        -u --upload=to_upload     - (Connecting) File for connecting client to 
                                    stream to listening server.
                                    Note that client will not stream a file if an initial
                                    command is assigned. Use one or the other
                                    
        -l --listen               - Run as listening server for incoming connections. By
                                    default, attempts to run first sent data stream
                                    as a command
        -w --write=write_to       - (Listening) Overrides default initial run function. 
                                    On connection, write initial stream to [write_to]
        -e --execute=file_to_exe  - (Listening) On connection, execute [file_to_exe]. 
                                    Can be used to run a recently streamed file. 
                                    (This is the last thing performed on initial connection)
        -s --shell                - (Listening) Initialize an interactive
                                    command shell, and send responses to client
        --timeout                 - Timeout for listener to host connecting client
                                    (Default 60 seconds) 

        -v --verbose              - Increased Verbosity

        
        Shell Commands:
        
        bhpquit                   - Disconnect client from listening server
        bhpshutdown               - Shutdown listening post, disconnect server 
            
        
        Note that this script will either connect or listen, as enabled by the first 
        opt given. Listening opts given to a connecting run will be ignored, 
        and vice versa  
        
        Examples:
        bhpnet.py -t 192.168.0.1 -p 5555 -l -c
        bhpnet.py -t 192.168.0.1 -p 5555 -l -u=C:\\target.exe
        bhpnet.py -t 192.168.0.1 -p 5555 -s=C:\\to_send.exe
        bhpnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
        echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135
        """))
        sys.exit(0)

    # # # Listening functions

    def listening_server(self):
        """
        Start a TCP server socket, spool threads to handle incoming clients
        """
        if not self.target:
            self.target = '127.0.0.1'

        # Spool listening server
        server = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        server.bind((self.target, self.port))
        server.listen(5)

        self.verprint(f"[*] Listening on {self.target}:{self.port}")

        while self.listening_active:
            server_acceptance = server.accept()  # Tuple containing client_socket and addr
            if self.listening_active:
                client_thread = threading.Thread(target=self.listening_handle_connects,
                                                 args=(server_acceptance, ))
                client_thread.start()

    def listening_handle_connects(self, connected_client: Tuple[socket.socket, any]):
        """
        Called by server socket in server for each connection.
        File upload, command execution, and/or interactive shell through given client socket

        Args:
            connected_client: Answered socket and address from server.accept()
        """
        client_socket, addr = connected_client
        client_socket.settimeout(self.timeout)
        closing = b''

        try:

            self.verprint(f'--[*] Accepted connection, handler spooled for {addr[0]}:{addr[1]}')
            buffer_stream = self.receive_data(client_socket)
            """Received buffer stream from connecting client"""
            response = b''
            """First response to send to connecting client"""

            if not self.write_to:
                # Default first action...
                response = self.bin_join(self.run_command(buffer_stream), response)
            elif self.write_to:
                # Or write stream to file instead
                response = self.bin_join(self.listening_write_file(buffer_stream), response)

            if self.execute:
                # Try to execute a given file
                response = self.bin_join(self.run_command(self.execute), response)

            if not self.shell:
                # Listener not set to init shell. Send response and close
                self.send_data(client_socket, self.bin_join(
                    response, f"\nClosing connection to {self.target}:{self.port}"))
            else:
                # Initiate shell
                self.listening_shell_loop(client_socket, response)

        except CloseConnection:
            closing = dedent(f"""
            --[*] Client requested connection close
            ----- Closing handler {addr[0]}:{addr[1]}
            """)
        except ShutdownListen:
            closing = dedent(f"""
            --[*] Client {addr[0]}:{addr[1]} requested shutdown listening post
            ----- Shutting down
            """)
            self.listening_active = False
        except Exception as err:
            closing = dedent(f"""
            --[*] Unexpected error: {err}
            ----- Closing handler {addr[0]}:{addr[1]}
            """)
        finally:
            self.verprint(closing)
            # Low effort try to send to connected client
            try:
                self.send_data(client_socket, self.bin_join(closing))
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
            except Exception as err:
                self.verprint(f"Unexpected error while closing handler {addr[0]}:{addr[1]} : ")
                self.verprint(err)

    def listening_check_for_commands(self, stream: bytes):
        """
        Given a datastream, check if a closing command is in it. Raise appropriate handling error

        Args:
            stream: bytes stream sent from connecting client, to check for bhp commands
        """

        # Catch bhp specific commands in stream
        if self.close_connection in str(stream):
            raise CloseConnection
        if self.shutdown_listening in str(stream):
            raise ShutdownListen

    def listening_write_file(self, data_buffer) -> bytes:
        """
        If allowed, Extension to write a caught data_buffer to local file (self.write_to)
        Return feedback to calling functions

        Args:
            data_buffer: handle_connects's received data stream from it's client_socket.
        Returns:
            File write feedback, either successful or failure with error
                if write_to is None (i.e. not set) return empty bytes string
        """

        send_feedback = ''
        if self.write_to:
            try:
                with open(self.write_to, "wb") as file:
                    file.write(data_buffer)
                send_feedback = f"Successfully saved file to {self.write_to}\r\n"

            except Exception as err:
                send_feedback = f"""Failed to save file to {self.write_to}\r\n{err}\r\n"""

        return self.bin_join(send_feedback)

    def run_command(self, command: Union[str, bytes, None]) -> bytes:
        """
        Locally run given command using subprocess, and return results as bytes string

        Args:
            command: given command to run
        """
        if not command:
            command_run = ''
        elif isinstance(command, bytes):
            command_run = command.decode()
        else:
            command_run = command

        try:
            output = subprocess.check_output(command_run, stderr=subprocess.STDOUT, shell=True)
        except Exception as err:
            output = dedent(f"""
                Failed to execute command
                Command : {command_run}
                Error   : {err}\r\n""")

        return self.bin_join(output)

    def listening_shell_loop(self, client_socket: socket.socket, initial_response: bytes):
        """
        Function to handle one off commands from connecting client. Loops until connection broken.

        Args:
            client_socket: Answered socket to accept shell commands from
            initial_response: Initial response from handle_connects' steps, if any.
                Passed here so shell loop can return, with prompt characters
        """

        response = initial_response
        prompt = f'\n<BHP@{self.target}:{self.port}>#'

        while True:
            # Loop is broken by explicit errors or commands
            self.send_data(client_socket, self.bin_join(response, prompt))
            try:
                cmd_buffer = self.receive_data(client_socket)
                self.listening_check_for_commands(cmd_buffer)
                response = self.run_command(cmd_buffer)
            except TimeoutError:
                raise TimeoutError("Listening server timeout reached")
            except Exception as err:
                raise err

    # # # Connection Functions

    def connecting_client(self):
        """
        Spool up TCP socket, catch return data, prompt for new to_send. Rinse and repeat

        """
        # Create client socket, using IPv4 and TCP socket type
        client = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        try:
            self.verprint(f"Connecting to {self.target}:{self.port}")
            client.connect((self.target, self.port))

            to_send = b''
            if self.initial_cmd:
                to_send = self.bin_join(self.initial_cmd)
            elif self.upload:
                to_send = self.bin_join(self.connecting_file_stream())

            while True:
                # Loop broken by error or explicit command
                self.send_data(client, self.bin_join(to_send, '\n'))
                response = self.receive_data(client)
                self.bin_print('\n', response, end=' ')  # ' ' after shell-sent prompt characters
                to_send = input() + '\n'

        except KeyboardInterrupt as err:
            input(dedent(
                f"""{err}
                Press any key to close..."""))
        except ConnectionRefusedError:
            self.verprint('\nCannot connect, is listening active?')
        except ConnectionAbortedError:
            # Socket closed by listener
            pass
        except ConnectionResetError:
            self.verprint("Connection prematurely closed. Did listening shutdown?")
        finally:
            try:
                client.shutdown(socket.SHUT_RDWR)
                client.close()
            except Exception as err:
                self.verprint(f"Unexpected error when disconnecting from {self.target}:{self.port}")
                self.verprint(err)

    def connecting_file_stream(self):
        """
        Targets file self.upload and converts to binary stream, to be sent to listening server

        Returns: Single binary stream of indicated file
        """
        file_stream = b''
        with open(self.upload, 'rb') as file:
            for ndx, line in enumerate(file):
                file_stream = self.bin_join(file_stream, line)
        return file_stream + b'\r\n'

    # # # Shared functions

    @staticmethod
    def send_data(receiving_socket: socket.socket, data_stream: bytes) -> None:
        """
        Centralised function to handle sending data stream to receive data. Sends data in consistent
        buffer sizes
        Args:
            receiving_socket: Socket to send stream to
            data_stream: Data stream to send
        """

        data_fragments = []
        for i in range(0, len(data_stream), 4096):
            # Break data stream into byte sized bites
            data_fragments.append(data_stream[i:i + 4096])
        if data_fragments[-1] == 4096:
            # Make sure last fragment isn't BUFFER bytes long
            data_fragments.append(b'\n')
        for frag in data_fragments:
            receiving_socket.send(frag)

    @staticmethod
    def receive_data(sending_socket: socket.socket) -> bytes:
        """
        Centralised fuction to handle receiving one or more packet buffers from TCP socket
        Args:
            sending_socket: Socket sending stream to this instance.
        Returns:
              Complete binary stream from socket
        """
        stream = sending_socket.recv(4096)
        fragments: List[bytes] = [stream]
        while True:
            if len(stream) < 4096:
                break
            else:
                stream = sending_socket.recv(4096)
                fragments.append(stream)
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

    def main(self):
        """
        Primary logic loop. After init, builds listening post or starts connecting client
        """

        if self.listening:
            # Time to listen, potentially upload items, execute commands, and drop a shell back
            self.listening_server()

        else:
            # Try connecting to target, send a potential starting command
            self.connecting_client()


if __name__ == '__main__':
    nc = NC()
    nc.main()
