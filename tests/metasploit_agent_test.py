"""Unittests for agent Metasploit."""
import json

from ostorlab.agent.message import message
from ostorlab.utils import defintions as utils_definitions
from pytest_mock import plugin

from agent import metasploit_agent as msf_agent
from pymetasploit3 import msfrpc


def testExploitCheck_whenSafe_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    msfrpc_client: msfrpc.MsfRpcClient,
    safe_scan_message,
) -> None:
    """Unittest for agent metasploit"""
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("exploit/windows/http/exchange_proxyshell_rce").encode(),
        )
    ]

    agent_instance.process(safe_scan_message)

    assert len(agent_mock) == 0


def testAuxiliaryExecute_whenSafe_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    msfrpc_client: msfrpc.MsfRpcClient,
    safe_scan_message,
) -> None:
    """Unittest for agent metasploit"""
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("auxiliary/scanner/http/exchange_proxylogon").encode(),
        )
    ]

    agent_instance.process(safe_scan_message)

    assert len(agent_mock) == 0


def testAuxiliaryExecute_whenVulnerable_returnFindings(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    msfrpc_client: msfrpc.MsfRpcClient,
    vulnerable_scan_message,
    msf_console_output,
) -> None:
    """Unittest for agent metasploit"""
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("auxiliary/scanner/http/joomla_version").encode(),
        )
    ]
    mocker.patch(
        "pymetasploit3.msfrpc.MsfConsole.run_module_with_output",
        return_value=msf_console_output,
    )

    agent_instance.process(vulnerable_scan_message)

    assert len(agent_mock) == 1


def testAuxiliaryExecute_whenExtraArgsPassed_returnFindings(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    msfrpc_client: msfrpc.MsfRpcClient,
    vulnerable_scan_message,
    msf_console_output,
) -> None:
    """Unittest for agent metasploit"""
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("auxiliary/scanner/portscan/tcp").encode(),
        ),
        utils_definitions.Arg(
            name="PORTS",
            type="string",
            value=json.dumps("80,443").encode(),
        )
    ]

    agent_instance.process(vulnerable_scan_message)

    assert len(agent_mock) == 1
