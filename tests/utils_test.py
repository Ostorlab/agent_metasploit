"""Unit tests for metasploit agent utilities"""

from ostorlab.agent.message import message

from agent import utils


def testPrepareTargets_whenDomainAsset_returnResult(
    scan_message: message.Message,
) -> None:
    targets = utils.prepare_targets(scan_message)

    assert len(targets) > 0
    target = targets[0]
    assert target.host == "www.google.com"
    assert target.scheme == "https"
    assert target.port == 443


def testPrepareTargets_whenIPv4Asset_returnResult(
    metasploitable_scan_message: message.Message,
) -> None:
    targets = utils.prepare_targets(metasploitable_scan_message)

    assert len(targets) > 0
    target = targets[0]
    assert target.host == "192.168.1.17"
    assert target.scheme == "https"
    assert target.port == 443


def testPrepareTargets_whenIPv6Asset_returnResult(
    scan_message_ipv6: message.Message,
) -> None:
    targets = utils.prepare_targets(scan_message_ipv6)

    assert len(targets) > 0
    target = targets[0]
    assert target.host == "2001:db8:3333:4444:5555:6666:7777:8888"
    assert target.scheme == "https"
    assert target.port == 443


def testPrepareTargets_whenLinkAsset_returnResult(
    scan_message_link: message.Message,
) -> None:
    targets = utils.prepare_targets(scan_message_link)

    assert len(targets) > 0
    target = targets[0]
    assert target.host == "www.google.com"
    assert target.scheme == "https"
    assert target.port == 443
