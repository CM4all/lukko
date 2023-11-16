#!/usr/bin/env python3

import os
import sys
import signal
import subprocess
import time
from typing import Mapping, Sequence

import paramiko

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} BUILD_DIR", file=sys.stderr)
    sys.exit(1)

build_directory = sys.argv[1]

config_directory = os.path.join(os.path.dirname(__file__), 'config')

ssh = '/usr/bin/ssh'
dropbear_client = '/usr/bin/dbclient'

key_types = ('ed25519', 'ecdsa', 'rsa')

# protect the client keys so `ssh` doesn't complain
for key_type in key_types:
    os.chmod(os.path.join(config_directory, 'client', f'id_{key_type}'), 0o600)

def ssh_options(options: Mapping[str, str]) -> Sequence[str]:
    return [f'-o{name}={value}' for name, value in options.items()]

def ssh_cmdline(user: str, address: str, port: int,
                options: Mapping[str, str],
                cmdline: Sequence[str]) -> Sequence[str]:
    return [
        ssh,
        '-v',
        '-Fnone',
        *[f'-o{name}={value}' for name, value in options.items()],
        f'-p{port}',
        f'{user}@{address}',
        *cmdline,
    ]

def test_auth(user: str, address: str, port: int,
              options: Mapping[str, str]) -> None:
    subprocess.check_call(
        ssh_cmdline(user, address, port, options, ('true',)),
        stdout=sys.stderr,
        stdin=subprocess.DEVNULL,
        timeout=10,
    )

def test_openssh_client(user: str, address: str, port: int) -> None:
    options = {
        'BatchMode': 'yes',
        'UserKnownHostsFile': os.path.join(config_directory, 'client', 'known_hosts'),
        'IdentitiesOnly': 'yes',
        'IdentityFile': os.path.join(config_directory, 'client', f'id_ed25519'),

        # this is necessary or else OpenSSH will not use RSA keys (not
        # even with SHA2)
        'PubkeyAcceptedAlgorithms': '+ssh-rsa',
    }

    # test all client key types
    for key_type in key_types:
        options2 = dict(options)
        options2['IdentityFile'] = os.path.join(config_directory, 'client', f'id_{key_type}')
        test_auth(user, address, port, options2)

    # test all combinations of kex, host key algorithm, cipher
    options2 = dict(options)
    for kex in ('curve25519-sha256', 'ecdh-sha2-nistp256'):
        options2['KexAlgorithms'] = kex

        for host_key_algorithm in ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-rsa'):
            options2['HostKeyAlgorithms'] = host_key_algorithm

            for cipher in ('chacha20-poly1305@openssh.com',
                           'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
                           'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'):
                options2['Ciphers'] = cipher
                test_auth(user, address, port, options2)

def test_dropbear_client(user: str, address: str, port: int) -> None:
    for key_type in key_types:
        for cipher in ('chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes256-ctr'):
            subprocess.check_call(
                [
                    dropbear_client, '-p', str(port),
                    '-i', os.path.join(config_directory, 'dropbear', f'id_{key_type}'),
                    '-c', cipher,
                    '-y',
                    f'{user}@{address}',
                    'true',
                ],
                stdout=sys.stderr,
                stdin=subprocess.DEVNULL,
                timeout=10,
            )

def test_paramiko(user: str, address: str, port: int) -> None:
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys(os.path.join(config_directory, 'client', 'known_hosts'))
    ssh.connect(hostname=address, port=port, username=user,
                key_filename=os.path.join(config_directory, 'client', 'id_ed25519'),
                timeout=10, look_for_keys=False)

    sftp = ssh.open_sftp()
    sftp.lstat('.')
    sftp.chdir('/')
    sftp.lstat('.')
    sftp.getcwd()
    sftp.close()

    stdin, stdout, stderr = ssh.exec_command('echo hello')
    stdin.close()
    stdout.read()
    stdout.close()
    stderr.read()
    stderr.close()

def test_ruby_net_ssh(user: str, address: str, port: int) -> None:
    subprocess.check_call(
        [
            os.path.join(os.path.dirname(__file__), 'test_ruby.rb'),
            user, address, str(port),
            os.path.join(config_directory, 'client', 'id_ed25519'),
        ],
        stdin=subprocess.DEVNULL,
        timeout=10,
    )

def run_tests(user: str, address: str, port: int) -> None:
    test_openssh_client(user, address, port)
    test_dropbear_client(user, address, port)
    test_paramiko(user, address, port)
    test_ruby_net_ssh(user, address, port)

    # TODO:
    # - more sftp commands
    # - TCP forwarding
    # - password auth
    # - hostbased auth
    # - pty
    # - stdin, stdout, stderr

process = subprocess.Popen(
    [
        os.path.join(build_directory, 'cm4all-lukko'),
        '--config', os.path.join(config_directory, 'server', 'lukko.conf'),
    ],
    stdin=subprocess.DEVNULL,
    env={},
)

# wait for startup to finish
time.sleep(0.1)

run_tests(os.environ['USER'], '127.0.0.1', 2200)

os.kill(process.pid, signal.SIGTERM)
process.wait(10)
process.kill()
