"""Utilities for agent Metasploit"""
import random
import string
import subprocess
from urllib import parse as urlparser

from ostorlab.agent.message import message as m

from pymetasploit3 import msfrpc

SCHEME_TO_PORT = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "pop3": 110,
    "imap": 143,
    "irc": 6667,
    "mysql": 3306,
    "postgres": 5432,
    "redis": 6379,
    "mongodb": 27017,
    "ldap": 389,
    "sftp": 22,
    "vnc": 5900,
    "git": 9418,
}
DEFAULT_PORT = 443


def _get_port(message: m.Message) -> int:
    """Returns the port to be used for the target."""
    if message.data.get("port") is not None:
        return int(message.data["port"])
    else:
        return DEFAULT_PORT


def prepare_target(message: m.Message) -> tuple[str, int]:
    """Prepare targets based on type, if a domain name is provided, port and protocol are collected
    from the config."""
    if (host := message.data.get("host")) is not None:
        port = _get_port(message)
        return host, port
    elif (host := message.data.get("name")) is not None:
        port = _get_port(message)
        return host, port
    elif (url := message.data.get("url")) is not None:
        parsed_url = urlparser.urlparse(url)
        host = parsed_url.netloc
        scheme = parsed_url.scheme
        port = SCHEME_TO_PORT.get(scheme) or DEFAULT_PORT
        return host, port
    else:
        raise NotImplementedError


def initialize_msf_rpc() -> msfrpc.MsfRpcClient:
    """Start msfrpcd and connect to it
    Args:

    Returns:
        - msfrpc client
    """
    subprocess.run(["pkill", "-f", "msfrpcd"], check=False)
    msfrpc_pwd = "".join([random.choice(string.ascii_letters) for _ in range(12)])
    command = ["msfrpcd", "-P", msfrpc_pwd, "-p", "55555"]
    subprocess.run(command, capture_output=False, check=False)
    client = msfrpc.MsfRpcClient(msfrpc_pwd, ssl=True, port=55555)
    return client
