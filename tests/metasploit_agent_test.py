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
def testExploit_whenSafe_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit auxiliary execute, case when target is safe"""
    agent_instance.process(scan_message)

    assert len(agent_mock) == 0


@pytest.mark.parametrize(
    "agent_instance", [["exploit/unix/misc/distcc_exec", []]], indirect=True
)
def testExploit_whenVulnerable_returnFindings(
    agent_instance: msf_agent.MetasploitAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
        "Target: 192.168.1.17:443\n"
        "Message: \n"
        "```\nThe target is vulnerable.\n```"
    )
    assert vulnerability_finding["references"] == [
        {
            "title": "https://nvd.nist.gov/vuln/detail/CVE-2004-2687",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2004-2687",
        },
        {
            "title": "http://distcc.samba.org/security.html",
            "url": "http://distcc.samba.org/security.html",
        },
    ]


@pytest.mark.parametrize(
    "agent_instance",
    [["exploit/windows/http/ws_ftp_rce_cve_2023_40044", []]],
    indirect=True,
)
def testExploit_whenCannotCheck_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    metasploitable_scan_message: message.Message,
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit exploit check, case when cannot check"""
    agent_instance.process(scan_message)

    assert len(agent_mock) == 0


@pytest.mark.parametrize(
    "agent_instance",
    [["auxiliary/scanner/ike/cisco_ike_benigncertain", []]],
    indirect=True,
)
def testExploit_whenDefaultAuxiliaryMessage_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit exploit check,
    case when console returns default auxiliary message"""
    agent_instance.process(scan_message)

    assert len(agent_mock) == 0


@pytest.mark.parametrize(
    "agent_instance",
    [["auxiliary/scanner/ssl/openssl_heartbleed", []]],
    indirect=True,
)
def testAuxiliary_whenSafe_returnNone(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message: message.Message,
) -> None:
    """Unit test for agent metasploit exploit check,
    case when console returns default auxiliary message"""
    agent_instance.process(scan_message)

    assert len(agent_mock) == 0


@pytest.mark.parametrize(
    "agent_instance",
    [["auxiliary/scanner/ssl/openssl_heartbleed", []]],
    indirect=True,
)
def testAuxiliary_whenAppearsVulnerable_returnFindings(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for agent metasploit auxiliary check,
    case when console returns default auxiliary message"""
    mocker.patch(
        "pymetasploit3.msfrpc.MsfModule.check_exploit",
        return_value={"job_id": 10, "uuid": "CzwatViyCW2tJABg0FiYfHeC"},
    )
    mocker.patch(
        "pymetasploit3.msfrpc.JobManager.info_by_uuid",
        return_value={
            "status": "completed",
            "result": {
                "code": "appears",
                "message": "The target appears to be vulnerable.",
                "reason": None,
                "details": {},
            },
        },
    )

    agent_instance.process(scan_message)

    assert len(agent_mock) == 1
    vulnerability_finding = agent_mock[0].data
    assert (
        vulnerability_finding["title"]
        == "OpenSSL Heartbeat (Heartbleed) Information Leak"
    )
    assert vulnerability_finding["risk_rating"] == "HIGH"
    assert "scanner/ssl/openssl_heartbleed" in vulnerability_finding["technical_detail"]
    assert (
        "The target appears to be vulnerable."
        in vulnerability_finding["technical_detail"]
    )


@pytest.mark.parametrize(
    "agent_instance",
    [["exploit/windows/http/exchange_proxyshell_rce", []]],
    indirect=True,
)
def testMetasploitAgent_whenSameMessageSentTwice_shouldScanOnlyOnce(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test MetasploitAgent agent should not scan the same message twice."""
    connect_msfrpc_mock = mocker.patch("agent.utils.connect_msfrpc")

    agent_instance.process(scan_message)
    agent_instance.process(scan_message)

    connect_msfrpc_mock.assert_called_once()


@pytest.mark.parametrize(
    "agent_instance",
    [["exploit/windows/http/exchange_proxyshell_rce", []]],
    indirect=True,
)
def testMetasploitAgent_whenUnknownTarget_shouldNotBeProcessed(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test MetasploitAgent agent should not scan message with unknown target."""

    connect_msfrpc_mock = mocker.patch("agent.utils.connect_msfrpc")
    msg = message.Message.from_data(
        "v3.asset.file", data={"path": "libagora-crypto.so"}
    )

    agent_instance.process(msg)

    connect_msfrpc_mock.assert_not_called()


@pytest.mark.parametrize(
    "agent_instance",
    [["exploit/windows/http/exchange_proxyshell_rce", []]],
    indirect=True,
)
def testExploit_whenHostNotExist_returnCorrectMessage(
    agent_instance: msf_agent.MetasploitAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_host_not_exist: message.Message,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unit test for agent metasploit exploit check, case when target is not exist"""
    agent_instance.process(scan_message_host_not_exist)

    assert len(agent_mock) == 0
    assert "The specified target sa.com is not valid" in caplog.text
