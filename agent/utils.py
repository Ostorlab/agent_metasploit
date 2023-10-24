"""Utilities for agent Metasploit"""
import random
import string
import subprocess

from pymetasploit3 import msfrpc


def initialize_msf_rpc() -> msfrpc.MsfRpcClient:
    """Start msfrpcd and connect to it"""
    msfrpc_pwd = "".join([random.choice(string.ascii_letters) for _ in range(12)])
    command = ["msfrpcd", "-P", msfrpc_pwd, "-p", "55552"]
    subprocess.run(command, capture_output=True)
    client = msfrpc.MsfRpcClient(msfrpc_pwd, ssl=True, port=55552)
    return client
