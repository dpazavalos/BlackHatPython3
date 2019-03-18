import threading
import paramiko
import subprocess
import socket
from typing import List, Optional
import getpass

# # #

# # # Common send/recv functions

# # #


def send_data(*, to_socket: socket.socket, data_stream: bytes,
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


def receive_data(*, from_socket: socket.socket,
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

# # #

# # # SSHv2 functions, using paramiko API

# # #


def ssh_command(*,
                ip: str = None, port: int = None, user: str = None, password: str = None,
                command: str = None, known_hosts: Optional[str] = None):
    """
    Non-interactive SSH command client, using paramiko API. Connects and sends single command to
    target ssh

    Args:
        ip:
            target IP                       (Def localhost)
        port:
            target port                     (Def 22)
        user:
            Username to pass to target IP   (Def running user)
        password:
            password to pass to target IP   (Def '')
        command:
            One shot command to pass        (Def ll /)
        known_hosts:
            Optional key support, using absolute path to .ssh/known_hosts
    """

    if not ip:
        ip = 'localhost'
    if not port:
        port = 22
    if not user:
        user = getpass.getuser()
    if not password:
        password = ''
    if not command:
        command = 'whoami'

    # Bind new SSH client
    client = paramiko.SSHClient()

    # Optional key support
    if known_hosts:
        client.load_host_keys(known_hosts)

    # Auto add missing keys
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect
    client.connect(ip, port=port, username=user, password=password)

    # request a new channel to server, session type
    ssh_session = client.get_transport().open_session()

    if ssh_session.active:
        ssh_session.exec_command(command)
        server_response = receive_data(from_socket=ssh_session)
        # server_response = ssh_session.recv(1024)
        print(server_response)


ssh_command(port=2222, password='toor', command='id')
