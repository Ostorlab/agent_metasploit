"""Utilities for agent Metasploit"""
import dataclasses
from typing import cast
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
DEFAULT_SCHEME = "https"


@dataclasses.dataclass
class Target:
    host: str
    scheme: str
    port: int


def _get_port(message: m.Message) -> int:
    """Returns the port to be used for the target."""
    if message.data.get("port") is not None:
        return int(message.data["port"])
    else:
        return DEFAULT_PORT


def _get_scheme(message: m.Message) -> str:
    """Returns the schema to be used for the target."""
    protocol = message.data.get("protocol")
    if protocol is not None:
        return str(protocol)

    schema = message.data.get("schema")
    if schema is None:
        return DEFAULT_SCHEME
    if schema in [
        "https?",
        "ssl/https-alt?",
        "ssl/https-alt",
        "https-alt",
        "https-alt?",
    ]:
        return "https"
    if schema in ["http?", "http"]:
        return "http"
    return str(schema)


def get_unique_check_key(message: m.Message) -> str | None:
    """Compute a unique key for a target"""
    if message.data.get("url") is not None:
        target = _get_target_from_url(message)
        if target is not None:
            return f"{target.scheme}_{target.host}_{target.port}"
    elif message.data.get("name") is not None:
        port = _get_port(message)
        schema = _get_scheme(message)
        domain = message.data["name"]
        return f"{schema}_{domain}_{port}"
    return None


def _get_target_from_url(message: m.Message) -> Target | None:
    """Compute schema and port from a URL"""
    url = message.data["url"]
    parsed_url = urlparser.urlparse(url)
    if parsed_url.scheme not in SCHEME_TO_PORT:
        return None
    schema = parsed_url.scheme or DEFAULT_SCHEME
    schema = cast(str, schema)
    domain_name = urlparser.urlparse(url).netloc
    port = 0
    if len(parsed_url.netloc.split(":")) > 1:
        domain_name = parsed_url.netloc.split(":")[0]
        if (
            len(parsed_url.netloc.split(":")) > 0
            and parsed_url.netloc.split(":")[-1] != ""
        ):
            port = int(parsed_url.netloc.split(":")[-1])
    args_port = _get_port(message)
    port = port or SCHEME_TO_PORT.get(schema) or args_port
    target = Target(host=domain_name, scheme=schema, port=port)
    return target


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
