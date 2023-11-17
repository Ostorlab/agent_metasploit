"""Pytest fixtures for agent Metasploit"""
import pathlib
import random
from typing import Any

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import metasploit_agent as msf_agent


@pytest.fixture()
def agent_instance(request: Any) -> msf_agent.MetasploitAgent:
    module = request.param[0]
    options = request.param[1]
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/metasploit",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )
        settings.args = [
            utils_definitions.Arg(
                name="config",
                type="array",
                value=bytes(
                    '[{"module": "%s", "options": %s}]' % (module, options),
                    encoding="utf-8",
                ),
            )
        ]
        return msf_agent.MetasploitAgent(definition, settings)


@pytest.fixture()
def agent_multi_instance(request: Any) -> msf_agent.MetasploitAgent:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/metasploit",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )
        settings.args = [
            utils_definitions.Arg(
                name="config",
                type="array",
                value=bytes(
                    '[{"module":"auxiliary/scanner/portscan/tcp",'
                    '"options":[{"name":"PORTS","value":"80,443"}]}, '
                    '{"module":"auxiliary/scanner/http/enum_wayback",'
                    '"options":[{"name":"DOMAIN","value":"www.ostorlab.co"}]}]',
                    encoding="utf-8",
                ),
            )
        ]
        return msf_agent.MetasploitAgent(definition, settings)


@pytest.fixture()
def scan_message() -> message.Message:
    """Creates a message of type v3.asset.domain_name.service to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name.service"
    msg_data = {"schema": "https", "name": "www.google.com", "port": 443}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_link() -> message.Message:
    """Creates a message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {"url": "https://www.google.com", "method": "POST"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6() -> message.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "120",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def metasploitable_scan_message() -> message.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "32", "version": 4}
    return message.Message.from_data(selector, data=msg_data)
