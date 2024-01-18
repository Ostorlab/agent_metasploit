#!/usr/bin/env python3

from pymetasploit3.msfrpc import *  # noqa: F403


def test_module_list(client):
    exs = client.modules.exploits
    assert "windows/smb/ms08_067_netapi" in exs


def test_module_options(client):
    ex = client.modules.use("exploit", "windows/smb/ms08_067_netapi")
    assert "Proxies" in ex.options
    assert "RHOSTS" in ex.required


def test_module_settings(client):
    ex = client.modules.use("exploit", "windows/smb/ms08_067_netapi")
    ex["RHOSTS"] = "127.0.0.1"
    opts = ex.runoptions
    assert opts["RHOSTS"] == "127.0.0.1"


def test_module_rpc_info(client):
    modinfo = client.call(
        MsfRpcMethod.ModuleInfo,
        ["exploit", "windows/smb/ms08_067_netapi"],  # noqa: F405
    )
    assert (
        modinfo["name"]
        == "MS08-067 Microsoft Server Service Relative Path Stack Corruption"
    )


def test_module_all_info(client):
    ex = client.modules.use("exploit", "windows/smb/ms08_067_netapi")
    assert "options" in ex._info
