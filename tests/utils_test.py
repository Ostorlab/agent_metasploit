"""Unit tests for metasploit agent utilities"""
from ostorlab.agent.message import message

from agent import utils


def testPrepareTarget_whenDomainAsset_returnResult(
    scan_message: message.Message,
) -> None:
    rhost, rport = utils.prepare_target(scan_message)

    assert rhost == "www.google.com"
    assert rport == 443


def testPrepareTarget_whenIPv4Asset_returnResult(
    metasploitable_scan_message: message.Message,
) -> None:
    rhost, rport = utils.prepare_target(metasploitable_scan_message)

    assert rhost == "192.168.1.17"
    assert rport == 443


def testPrepareTarget_whenIPv6Asset_returnResult(
    scan_message_ipv6: message.Message,
) -> None:
    rhost, rport = utils.prepare_target(scan_message_ipv6)

    assert rhost == "2001:db8:3333:4444:5555:6666:7777:8888"
    assert rport == 443


def testPrepareTarget_whenLinkAsset_returnResult(
    scan_message_link: message.Message,
) -> None:
    rhost, rport = utils.prepare_target(scan_message_link)

    assert rhost == "www.google.com"
    assert rport == 443
