"""
* Limited python implementation of SSHv2 API Paramiko, for a self standing SSH client/server setup *

Usage: bhpnet.py -t target_host -p port

-h --help           Show this help page

-t -target          Target IP   (Def : Localhost)

-p -port            Target Port (Def : 9999)

--user=uname        username to use (Def : Running user)

--pass=pword        password to sign in with (Def : None)

-b --banner         Banner Mode Enabled. Client listens for a banner, Server sends one

-k=known_hosts      Optional key support, provide absolute path to .ssh/known_hosts

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
from typing import Tuple, Union, List


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
            opts, args = getopt.getopt(sys.argv[1:], "ht:p:k:bci:u:lw:e:sv",
                                       ['help', 'target=', 'port=', 'user=', 'pass=', 'banner'
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
                    self.__setattr__('port', int(arg))

                elif opt in ('-c', '--connecting'):
                    # self.connecting = True
                    self.__setattr__('connecting', True)

                elif opt == 'k':
                    # self.known_hosts = arg
                    self.__setattr__('known_hosts', arg)

                elif opt == 'user':
                    # self.user = arg
                    self.__setattr__('user', arg)

                elif opt in ('b', '--banner'):
                    # self.banner = True
                    self.__setattr__('banner', True)

                elif opt == 'pass':
                    # self.password = arg
                    self.__setattr__('password', arg)

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
    port: int = 2222
    """Target port"""
    known_hosts = ''
    """Optional key support, using absolute path to .ssh/known_hosts"""
    user: str = getpass.getuser()
    """Username to pass to custom server"""
    password: str = None
    """password to sign in with"""
    banner: bool = False
    """Banner Mode Enabled. Client listens for a banner, Server sends one"""

    # Connecting functions
    connecting: bool = False
    """Bool to connect to listening server on [host]:[port]"""
    upload: str = ''
    """File to upload to listening server"""
    initial_cmd: str = 'whoami'
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


class ShutdownServer(socket.error):
    """Custom error used to shutdown listening server"""


class ShutdownClient(socket.error):
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
            child = SSHServer()
            child.server()

        else:
            # Try connecting to target, send a potential starting command
            child = SSHClient()
            child.client()


class SSHServer(SSHCustom, paramiko.ServerInterface):
    """Custom SSH client, using Paramiko API wrapper"""

    def __init__(self):
        super(SSHServer, self).__init__()

        # Extension to super init, name spacing an Event
        self.event = threading.Event()

        self.rsa_key = paramiko.RSAKey(filename='07_test_rsa.key')
        """Server RSA Key"""

        self.welcome_banner = b'A python SSH Server'

    def check_channel_request(self, kind, chanid):
        # ServInt override, enable simple check channel request
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # ServInt override, bind auth check to our super namespace attributes
        if (username == self.atts.user) and (password == self.atts.password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def server(self):
        """
        Start a TCP server socket, spool threads to handle incoming clients
        """

        self.verprint(f"[*] Listening on {self.atts.target}:{self.atts.port}")
        try:
            # Spool main SSH server
            server = socket.socket()

            # Bind socket settings
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.atts.target, self.atts.port))
            server.listen(5)

            while self.atts.listening_active:
                server_acceptance = server.accept()  # Tuple containing client_socket and addr
                if self.atts.listening_active:
                    client_thread = threading.Thread(target=self.handle_connects,
                                                     args=(server_acceptance,))
                    client_thread.start()
        except ShutdownServer:
            print("")

        except Exception as err:
            closing = dedent(f"""
                --[*] Unexpected error: {err}
                ----- Closing server""")
            self.verprint(closing)

    def handle_connects(self, connected_client: Tuple[socket.socket, any]):

        # Identify target TCP connection
        client_socket, addr = connected_client
        client_socket.settimeout(self.atts.timeout)
        self.verprint(f'--[*] Accepted connection, handler spooled for {addr[0]}:{addr[1]}')

        try:
            # Create SSH transport object over client_socket
            ssh_session = paramiko.Transport(client_socket)
            ssh_session.add_server_key(self.rsa_key)
            ssh_session.start_server()
            ssh_channel = ssh_session.accept(20)

            if self.atts.banner:
                self.help.send_data(ssh_channel, self.welcome_banner)

            buffer_stream = self.help.receive_data(ssh_channel)
            """Received buffer stream from connecting client"""
            response = b''
            """First response to send to connecting client"""

            if not self.atts.write_to:
                # Default first action...
                response = self.help.bin_join(self.run_command(buffer_stream), response)
            elif self.atts.write_to:
                # Or write stream to file instead
                response = self.help.bin_join(self.write_file(buffer_stream), response)

            if self.atts.execute:
                # Try to execute a given file
                response = self.help.bin_join(self.run_command(self.atts.execute), response)

            # Determine if server set to init shell or not. Respond either way
            if not self.atts.shell:
                response = self.help.bin_join(
                    response, f"\nClosing connection to {self.atts.target}:{self.atts.port}")
                self.help.send_data(to_socket=ssh_channel, data_stream=response)
            else:
                self.shell_loop(ssh_channel, response)

        # # # Exception Handling

        except paramiko.SSHException:
            closing = dedent(f"""
            --[*] Unable to to negotiate SSH connection
            ----- Closing handler {addr[0]}:{addr[1]}
            """)

        except ShutdownClient:
            closing = dedent(f"""
            --[*] Client requested connection close
            ----- Closing handler {addr[0]}:{addr[1]}
            """)
        except ShutdownServer:
            closing = dedent(f"""
            --[*] Client {addr[0]}:{addr[1]} requested shutdown listening post
            ----- Shutting down
            """)
            # self.atts.listening_active = False
            raise ShutdownServer
        except Exception as err:
            closing = dedent(f"""
            --[*] Unexpected error: {err}
            ----- Closing handler {addr[0]}:{addr[1]}
            """)
        finally:
            self.verprint(closing)
            # Low effort try to send to connected client
            try:
                self.help.send_data(to_socket=ssh_channel,
                                    data_stream=self.help.bin_join(closing))
                # client_socket.shutdown(socket.SHUT_RDWR)
                # client_socket.close()
                ssh_channel.close()
            except Exception as err:
                self.verprint(f"Unexpected error while closing handler {addr[0]}:{addr[1]} : ")
                self.verprint(err)

    def check_for_commands(self, stream: bytes):
        """
        Given a datastream, check if a closing command is in it. Raise appropriate handling error

        Args:
            stream: bytes stream sent from connecting client, to check for bhp commands
        """

        # Catch bhp specific commands in stream
        if self.atts.close_connection in str(stream):
            raise ShutdownClient
        if self.atts.shutdown_listening in str(stream):
            raise ShutdownServer

    def write_file(self, data_buffer) -> bytes:
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

    def shell_loop(self, client_socket: socket.socket, initial_response: bytes):
        """
        Function to handle one off commands from connecting client. Loops until connection broken.

        Args:
            client_socket: Answered socket to accept shell commands from
            initial_response: Initial response from handle_connects' steps, if any.
                Passed here so shell loop can return, with prompt characters
        """

        response = initial_response
        prompt = f'\n<BHP@{self.atts.target}:{self.atts.port}>#'

        while True:
            # Loop is broken by explicit errors or commands
            self.help.send_data(to_socket=client_socket,
                                data_stream=self.help.bin_join(response, prompt))
            try:
                cmd_buffer = self.help.receive_data(from_socket=client_socket)
                self.check_for_commands(cmd_buffer)
                response = self.run_command(cmd_buffer)
            except TimeoutError:
                raise TimeoutError("Listening server timeout reached")
            except Exception as err:
                raise err


class SSHClient(SSHCustom):
    """Custom SSH Client, , using paramiko API wrapper"""

    def client(self):
        """
        Spool up TCP socket, catch return data, prompt for new to_send. Rinse and repeat
        """

        self.verprint(f"Connecting to {self.atts.target}:{self.atts.port}...")

        # Bind new SSH client
        client = paramiko.SSHClient()
        try:
            # Optional key support
            if self.atts.known_hosts:
                client.load_host_keys(self.atts.known_hosts)

            # Auto add missing keys
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect
            client.connect(self.atts.target, port=self.atts.port,
                           username=self.atts.user, password=self.atts.password)

            # request session channel to server
            ssh_session = client.get_transport().open_session()

            # Catch banner
            if self.atts.banner:
                banner = self.help.receive_data(ssh_session)
                self.help.bin_print(banner)

            # Build initial data to send
            if self.atts.upload:
                to_send = self.file_stream()
            else:
                to_send = self.help.bin_join(self.atts.initial_cmd, '\n')

            # Primary running loop
            while True:
                self.help.send_data(ssh_session, to_send)
                server_response = self.help.receive_data(ssh_session)
                self.help.bin_print('\n', server_response, end=' ')
                to_send = input() + '\n'

        # # # Exception Handling

        except KeyboardInterrupt:
            self.verprint("Disconnecting")
            pass
        except ConnectionRefusedError:
            self.verprint('Cannot connect, is listening active?')
        except ConnectionAbortedError:
            # Socket closed by listener
            self.verprint("Closing connection...")
        except ConnectionResetError:
            self.verprint("Connection prematurely closed. Did server shutdown?")
        except Exception as err:
            self.verprint("Unknown error!\n", err, "\nDisconnecting")
        finally:
            try:
                # client.shutdown(socket.SHUT_RDWR)
                # ssh_session.close()
                client.close()
            except Exception as err:
                self.verprint(
                    f"Unexpected error when disconnecting from {self.atts.target}:{self.atts.port}")
                self.verprint(err)

    def file_stream(self):
        """
        Targets file at upload and converts to binary stream, to send to listening server

        Returns:
                Single binary stream of indicated file
        """
        file_stream = b''
        with open(self.atts.upload, 'rb') as file:
            for ndx, line in enumerate(file):
                file_stream = self.help.bin_join(file_stream, line)
        return file_stream + b'\r\n'


if __name__ == '__main__':
    nc = SSHCustom()
    nc.main()
