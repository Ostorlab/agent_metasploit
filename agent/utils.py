"""Utilities for agent Metasploit"""
import random
import string
import subprocess

from pymetasploit3 import msfrpc


def initialize_msf_rpc() -> msfrpc.MsfRpcClient:
    """Start msfrpcd and connect to it
    Args:

    Returns:
        - msfrpc client
    """
    msfrpc_pwd = "".join([random.choice(string.ascii_letters) for _ in range(12)])
    command = ["msfrpcd", "-P", msfrpc_pwd, "-p", "55557"]
    subprocess.run(command, capture_output=False, check=False)
    client = msfrpc.MsfRpcClient(msfrpc_pwd, ssl=True, port=55557)
    return client
