import pytest
import subprocess
from pymetasploit3 import msfrpc

MSFRPCD_PWD = "Ostorlab123"


@pytest.fixture(scope="module")
def client() -> msfrpc.MsfRpcClient:
    """Start msfrpcd and connect to it"""
    subprocess.run(["pkill", "-f", "msfrpcd"], check=False)
    command = ["msfrpcd", "-P", MSFRPCD_PWD, "-p", "55552"]
    subprocess.run(command, capture_output=False, check=False)
    client = msfrpc.MsfRpcClient(MSFRPCD_PWD, ssl=True, port=55552)
    return client
