"""Pytest fixtures for agent Metasploit"""
import pathlib
import random
import string
import subprocess

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from pymetasploit3 import msfrpc
from pytest_mock import plugin

from agent import metasploit_agent as msf_agent

MSFRPCD_PWD = "Ostorlab123"


@pytest.fixture(scope="module")
def msfrpc_client() -> msfrpc.MsfRpcClient:
    command = ["msfrpcd", "-P", MSFRPCD_PWD, "-p", "55552"]
    subprocess.run(command, shell=True, check=True, capture_output=True)
    client = msfrpc.MsfRpcClient(MSFRPCD_PWD, ssl=True, port=55552)
    return client


@pytest.fixture()
def agent_instance(
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    msfrpc_client: msfrpc.MsfRpcClient,
) -> msf_agent.MetasploitAgent:
    mocker.patch("agent.utils.initialize_msf_rpc", return_value=msfrpc_client)
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/semgrep",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )
        return msf_agent.MetasploitAgent(definition, settings)


@pytest.fixture()
def safe_scan_message() -> message.Message:
    """Creates a message of type v3.asset.domain_name.service to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name.service"
    msg_data = {"schema": "https", "name": "www.google.com", "port": 443}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def vulnerable_scan_message() -> message.Message:
    """Creates a message of type v3.asset.domain_name.service to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name.service"
    msg_data = {"schema": "http", "name": "localhost", "port": 80}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def msf_console_output() -> str:
    return """VERBOSE => false
RPORT => 80
SSL => false
UserAgent => Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15
HttpUsername => 
HttpPassword => 
DigestAuthIIS => true
SSLVersion => Auto
FingerprintCheck => true
DOMAIN => WORKSTATION
HttpTrace => false
HttpTraceHeadersOnly => false
HttpTraceColors => red/blu
HTTP::uri_encode_mode => hex-normal
HTTP::uri_full_url => false
HTTP::pad_method_uri_count => 1
HTTP::pad_uri_version_count => 1
HTTP::pad_method_uri_type => space
HTTP::pad_uri_version_type => space
HTTP::method_random_valid => false
HTTP::method_random_invalid => false
HTTP::method_random_case => false
HTTP::version_random_valid => false
HTTP::version_random_invalid => false
HTTP::uri_dir_self_reference => false
HTTP::uri_dir_fake_relative => false
HTTP::uri_use_backslashes => false
HTTP::pad_fake_headers => false
HTTP::pad_fake_headers_count => 0
HTTP::pad_get_params => false
HTTP::pad_get_params_count => 16
HTTP::pad_post_params => false
HTTP::pad_post_params_count => 16
HTTP::shuffle_get_params => false
HTTP::shuffle_post_params => false
HTTP::uri_fake_end => false
HTTP::uri_fake_params_start => false
HTTP::header_folding => false
TARGETURI => /
THREADS => 1
ShowProgress => true
ShowProgressPercent => 10
RHOSTS => 127.0.0.1
VHOST => localhost
[!] Unknown datastore option: DisablePayloadHandler.
DisablePayloadHandler => True
WORKSPACE => ostorlab
[*] Server: Apache
[+] Joomla version: 1.0
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
"""
