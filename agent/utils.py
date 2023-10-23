"""Utilities for agent Metasploit"""
import random
import string
import subprocess
from pymetasploit3 import msfrpc


def initialize_msf_rpc():
    msfrpc_pwd = "".join([random.choice(string.ascii_letters) for _ in range(12)])
    command = ["msfrpcd", "-P", msfrpc_pwd]
    subprocess.run(command, shell=True, check=True)
    client = msfrpc.MsfRpcClient(msfrpc_pwd, ssl=True)
    return client
