"""Utilities for agent Metasploit"""
from urllib import parse as urlparser

import tenacity
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
MSFRPCD_PWD = "Ostorlab123"
PROCESS_TIMEOUT = 300


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


@tenacity.retry(
    stop=tenacity.stop_after_attempt(5),
    wait=tenacity.wait_fixed(20),
    retry=tenacity.retry_if_exception_type(),
)
def connect_msfrpc() -> msfrpc.MsfRpcClient:
    """Connect to msfrpcd
    Returns:
        - msfrpc client
    """
    client = msfrpc.MsfRpcClient(MSFRPCD_PWD, ssl=True, port=55555)
    return client
