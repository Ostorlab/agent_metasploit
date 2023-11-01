"""Unit tests for agent Metasploit."""
import json

from ostorlab.agent.message import message
from ostorlab.utils import defintions as utils_definitions
from pytest_mock import plugin

from agent import metasploit_agent as msf_agent


def testExploitCheck_whenSafe_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit exploit check, case when target is safe"""
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("exploit/windows/http/exchange_proxyshell_rce").encode(),
        )
    ]

    agent_instance.process(scan_message)

    assert len(agent_mock) == 0


def testAuxiliaryExecute_whenSafe_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit auxiliary execute, case when target is safe"""
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("auxiliary/scanner/http/exchange_proxylogon").encode(),
        )
    ]

    agent_instance.process(scan_message)

    assert len(agent_mock) == 0


def testAuxiliaryExecute_whenVulnerable_returnFindings(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    scan_message: message.Message,
    auxiliary_console_output: str,
) -> None:
    """Unit test for agent metasploit auxiliary execute, case when target is vulnerable"""
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("auxiliary/scanner/http/joomla_version").encode(),
        )
    ]
    mocker.patch(
        "pymetasploit3.msfrpc.MsfConsole.run_module_with_output",
        return_value=auxiliary_console_output,
    )

    agent_instance.process(scan_message)

    assert len(agent_mock) == 1
    vulnerability_finding = agent_mock[0].data
    assert vulnerability_finding["title"] == "Joomla Version Scanner"
    assert vulnerability_finding["risk_rating"] == "HIGH"
    assert vulnerability_finding["technical_detail"] == (
        "Using `auxiliary` module `scanner/http/joomla_version`\n"
        "Target: www.google.com\n"
        "Message: \n"
        "[*] Server: Apache\n"
        "[+] Joomla version: 1.0\n"
        "[*] Scanned 1 of 1 hosts (100% complete)\n"
        "[*] Auxiliary module execution completed\n"
    )


def testExploitCheck_whenVulnerable_returnFindings(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    metasploitable_scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit exploit check, case when target is vulnerable"""
    mocker.patch(
        "pymetasploit3.msfrpc.MsfModule.check_exploit",
        return_value={"job_id": 10, "uuid": "CzwatViyCW2tJABg0FiYfHeC"},
    )
    mocker.patch(
        "pymetasploit3.msfrpc.JobManager.info_by_uuid",
        return_value={
            "status": "completed",
            "result": {
                "code": "vulnerable",
                "message": "The target is vulnerable.",
                "reason": None,
                "details": {},
            },
        },
    )
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("exploit/unix/misc/distcc_exec").encode(),
        )
    ]

    agent_instance.process(metasploitable_scan_message)

    assert len(agent_mock) == 1
    vulnerability_finding = agent_mock[0].data
    assert vulnerability_finding["title"] == "DistCC Daemon Command Execution"
    assert vulnerability_finding["risk_rating"] == "HIGH"
    assert vulnerability_finding["technical_detail"] == (
        "Using `exploit` module `unix/misc/distcc_exec`\n"
        "Target: 192.168.1.17\n"
        "Message: The target is vulnerable."
    )


def testExploitCheck_whenVulnerable_returnConsoleOutput(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    metasploitable_scan_message: message.Message,
    exploit_console_output: str,
) -> None:
    """Unit test for agent metasploit exploit check, case when target is vulnerable (console output)"""
    mocker.patch(
        "pymetasploit3.msfrpc.MsfModule.check_exploit",
        return_value={"job_id": 10, "uuid": "CzwatViyCW2tJABg0FiYfHeC"},
    )
    mocker.patch(
        "pymetasploit3.msfrpc.JobManager.info_by_uuid",
        return_value={"status": "completed", "result": None},
    )
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("exploit/unix/misc/distcc_exec").encode(),
        )
    ]
    mocker.patch(
        "pymetasploit3.msfrpc.MsfConsole.run_module_with_output",
        return_value=exploit_console_output,
    )

    agent_instance.process(metasploitable_scan_message)

    assert len(agent_mock) == 1
    vulnerability_finding = agent_mock[0].data
    assert vulnerability_finding["title"] == "DistCC Daemon Command Execution"
    assert vulnerability_finding["risk_rating"] == "HIGH"
    assert vulnerability_finding["technical_detail"] == (
        "Using `exploit` module `unix/misc/distcc_exec`\n"
        "Target: 192.168.1.17\n"
        "Message: \n"
        "[+] 192.168.1.17:3632 - The target is vulnerable.\n"
    )


def testAuxiliaryPortScan_whenResultsFound_returnOpenPorts(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    scan_message: message.Message,
    exploit_console_output: str,
) -> None:
    """Unit test for agent metasploit auxiliary run, case when results are found"""
    agent_instance.settings.args = [
        utils_definitions.Arg(
            name="module",
            type="string",
            value=json.dumps("auxiliary/scanner/portscan/tcp").encode(),
        ),
        utils_definitions.Arg(
            name="options",
            type="array",
            value=json.dumps('[{"name": "PORTS", "value": "443,80"}]').encode(),
        ),
    ]

    agent_instance.process(scan_message)

    assert len(agent_mock) == 1
    vulnerability_finding = agent_mock[0].data
    assert vulnerability_finding["title"] == "TCP Port Scanner"
    assert vulnerability_finding["risk_rating"] == "HIGH"
    assert "443 - TCP OPEN" in vulnerability_finding["technical_detail"]
    assert "Target: www.google.com" in vulnerability_finding["technical_detail"]
    assert (
        "[*] Auxiliary module execution completed"
        in vulnerability_finding["technical_detail"]
    )


def testPrepareTarget_whenDomainAsset_returnResult(
    agent_instance: msf_agent.MetasploitAgent, scan_message: message.Message
) -> None:
    rhost, rport = agent_instance.prepare_target(scan_message)

    assert rhost == "www.google.com"
    assert rport == 443


def testPrepareTarget_whenIPAsset_returnResult(
    agent_instance: msf_agent.MetasploitAgent,
    metasploitable_scan_message: message.Message,
) -> None:
    rhost, rport = agent_instance.prepare_target(metasploitable_scan_message)

    assert rhost == "192.168.1.17"
    assert rport == 443


def testPrepareTarget_whenLinkAsset_returnResult(
    agent_instance: msf_agent.MetasploitAgent, scan_message_link: message.Message
) -> None:
    rhost, rport = agent_instance.prepare_target(scan_message_link)

    assert rhost == "www.google.com"
    assert rport == 443
