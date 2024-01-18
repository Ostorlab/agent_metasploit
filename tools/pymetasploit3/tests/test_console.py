import pytest
import time

from pymetasploit3.msfrpc import *  # noqa: F403


@pytest.fixture()
def cid(client):
    c_id = client.call(MsfRpcMethod.ConsoleCreate)["id"]  # noqa: F405
    client.consoles.console(c_id).read()
    yield c_id
    destroy = client.call(MsfRpcMethod.ConsoleDestroy, [c_id])  # noqa: F405
    assert destroy["result"] == "success"


def test_consolelist(client):
    conlist = client.call(MsfRpcMethod.ConsoleList)  # noqa: F405
    assert "consoles" in conlist
    assert type(conlist["consoles"]) == list  # noqa: E721


def test_console_manager_list(client):
    conlist = client.consoles.list
    for x in conlist:
        assert "id" in x
        break


def test_console_is_busy(client, cid):
    assert client.consoles.console(cid).is_busy() == False  # noqa: E712


def test_console_manager_readwrite(client, cid):
    client.consoles.console(cid).write("show options")
    out = client.consoles.console(cid).read()["data"]
    timeout = 30
    counter = 0
    while counter < timeout:
        out += client.consoles.console(cid).read()["data"]
        if len(out) > 0:
            break
        time.sleep(1)
        counter += 1
    assert "Global Options" in out


def test_console_run_module(client, cid):
    x = client.modules.use("exploit", "unix/ftp/vsftpd_234_backdoor")
    x["RHOSTS"] = "127.0.0.1"
    out = client.consoles.console(cid).run_module_with_output(x, mode="exploit")
    assert type(out) == str  # noqa: E721
    assert (
        "[-] 127.0.0.1:21 - Exploit failed [unreachable]: Rex::ConnectionRefused The connection was refused by the remote host (127.0.0.1:21)."
        in out
    )
