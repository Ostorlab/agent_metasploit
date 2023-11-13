"""Unit tests for agent Metasploit."""
import pytest
from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import metasploit_agent as msf_agent


@pytest.mark.parametrize(
    "agent_instance",
    [["exploit/windows/http/exchange_proxyshell_rce", []]],
    indirect=True,
)
def testExploitCheck_whenSafe_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit exploit check, case when target is safe"""
    agent_instance.process(scan_message)

    assert len(agent_mock) == 0


@pytest.mark.parametrize(
    "agent_instance",
    [["auxiliary/scanner/http/exchange_proxylogon", []]],
    indirect=True,
)
def testAuxiliaryExecute_whenSafe_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit auxiliary execute, case when target is safe"""
    agent_instance.process(scan_message)

    assert len(agent_mock) == 0


@pytest.mark.parametrize(
    "agent_instance", [["auxiliary/scanner/http/joomla_version", []]], indirect=True
)
def testAuxiliaryExecute_whenVulnerable_returnFindings(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit auxiliary execute, case when target is vulnerable"""
    with open(
        "tests/msf_output/auxiliary.txt", encoding="utf-8"
    ) as auxiliary_output_file:
        mocker.patch(
            "pymetasploit3.msfrpc.MsfConsole.run_module_with_output",
            return_value=auxiliary_output_file.read(),
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
        "```\n"
        "[*] Server: Apache\n"
        "[+] Joomla version: 1.0\n"
        "[*] Scanned 1 of 1 hosts (100% complete)\n"
        "[*] Auxiliary module execution completed\n"
        "```"
    )


@pytest.mark.parametrize(
    "agent_instance", [["exploit/unix/misc/distcc_exec", []]], indirect=True
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

    agent_instance.process(metasploitable_scan_message)

    assert len(agent_mock) == 1
    vulnerability_finding = agent_mock[0].data
    assert vulnerability_finding["title"] == "DistCC Daemon Command Execution"
    assert vulnerability_finding["risk_rating"] == "HIGH"
    assert vulnerability_finding["technical_detail"] == (
        "Using `exploit` module `unix/misc/distcc_exec`\n"
        "Target: 192.168.1.17\n"
        "Message: \n"
        "```The target is vulnerable.```"
    )


@pytest.mark.parametrize(
    "agent_instance", [["exploit/unix/misc/distcc_exec", []]], indirect=True
)
def testExploitCheck_whenVulnerable_returnConsoleOutput(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    metasploitable_scan_message: message.Message,
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
    with open("tests/msf_output/exploit.txt", encoding="utf-8") as exploit_output_file:
        mocker.patch(
            "pymetasploit3.msfrpc.MsfConsole.run_module_with_output",
            return_value=exploit_output_file.read(),
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
        "```\n"
        "[+] 192.168.1.17:3632 - The target is vulnerable.\n"
        "```"
    )


@pytest.mark.parametrize(
    "agent_instance",
    [["auxiliary/scanner/portscan/tcp", '[{"name": "PORTS", "value": "443,80"}]']],
    indirect=True,
)
def testAuxiliaryPortScan_whenResultsFound_returnOpenPorts(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit auxiliary run, case when results are found"""
    agent_instance.process(scan_message)

    assert len(agent_mock) == 1
    vulnerability_finding = agent_mock[0].data
    assert vulnerability_finding["title"] == "TCP Port Scanner"
    assert vulnerability_finding["risk_rating"] == "HIGH"
    assert "443 - TCP OPEN" in vulnerability_finding["technical_detail"]
    assert "80 - TCP OPEN" in vulnerability_finding["technical_detail"]
    assert (
        "[*] Auxiliary module execution completed"
        in vulnerability_finding["technical_detail"]
    )


def testAgent_whenMultipleModulesUsed_returnFindings(
    agent_multi_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit auxiliary run, case when results are found"""
    agent_multi_instance.process(scan_message)

    assert len(agent_mock) == 2
    assert any("TCP Port Scanner" in finding.data["title"] for finding in agent_mock)
    assert any(finding.data["risk_rating"] == "HIGH" for finding in agent_mock)
    assert any(
        "443 - TCP OPEN" in finding.data["technical_detail"] for finding in agent_mock
    )
    assert any(
        "80 - TCP OPEN" in finding.data["technical_detail"] for finding in agent_mock
    )
    assert any(
        "[*] Auxiliary module execution completed" in finding.data["technical_detail"]
        for finding in agent_mock
    )
    assert any(
        "Archive.org Stored Domain URLs" in finding.data["title"]
        for finding in agent_mock
    )
    assert (
        "http://ostorlab.co/robots.txt" in finding.data["technical_detail"]
        for finding in agent_mock
    )


@pytest.mark.parametrize(
    "agent_instance",
    [["exploit/windows/http/ws_ftp_rce_cve_2023_40044", []]],
    indirect=True,
)
def testExploitCheck_whenCannotCheck_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit exploit check, case when target is safe"""
    agent_instance.process(scan_message)

    assert len(agent_mock) == 0
