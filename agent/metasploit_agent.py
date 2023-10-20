"""Ostorlab Agent implementation for metasploit"""
import logging
import pathlib
import random
import string
import tempfile
import urllib
import urllib.parse
from typing import Tuple, Any

import requests
from ostorlab.agent import agent
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from rich import logging as rich_logging
from urllib import parse as urlparser
from pymetasploit3 import msfrpc
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
import subprocess

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)

SCHEME_TO_PORT = {"http": 80, "https": 443}
DEFAULT_PORT = 443
COMMAND_TIMEOUT = 180


class Error(Exception):
    """Base custom error class."""


class ArgumentError(Error):
    """Error when a required argument is missing"""


class PayloadError(Error):
    """Errors related to metasploit payloads"""


def initialize_msf_rpc():
    msfrpc_pwd = "".join([random.choice(string.ascii_letters) for _ in range(12)])
    command = ["msfrpcd", "-P", msfrpc_pwd]
    subprocess.run(command, shell=True, check=True)
    client = msfrpc.MsfRpcClient(msfrpc_pwd, ssl=True)
    return client


class MetasploitAgent(
    agent.Agent, vuln_mixin.AgentReportVulnMixin, persist_mixin.AgentPersistMixin
):
    """Source map agent."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self.client = initialize_msf_rpc()
        self.lhost = ""

    def process(self, message: m.Message) -> None:
        """Trigger Source map enumeration and emit found findings

        Args:
            message: A message containing the path and the content of the file to be processed

        """
        if module := self.args.get("module") is None:
            raise ArgumentError("Metasploit module must be specified.")

        rhost, rport = self._prepare_target(message)

        module_type, module_name = module.split("/", 1)
        if module_type == "exploit":
            if module_name not in self.client.modules.exploits:
                raise ArgumentError("Requested metasploit module is not found.")
        elif module_type == "auxiliary":
            if module_name not in self.client.modules.auxiliary:
                raise ArgumentError("Requested metasploit module is not found.")
        else:
            raise ArgumentError("Metasploit module should be exploit or auxiliary.")

        selected_module = self.client.modules.use(module_type, module_name)
        logger.info("Selected metasploit module: %s", selected_module)
        selected_module["RHOSTS"] = rhost
        selected_module["RPORT"] = rport
        if len(selected_module.missing_required) > 0:
            raise ArgumentError(
                "The following arguments are missing: %s",
                str(selected_module.missing_required),
            )

        reverse_payloads = [
            payload
            for payload in selected_module.targetpayloads()
            if "reverse" in payload
        ]
        exec_payloads = [
            payload for payload in selected_module.targetpayloads() if "exec" in payload
        ]

        if self.args.get("payload") is not None:
            payload_name = self.args.get("payload")
        elif reverse_payloads:
            payload_name = reverse_payloads[0]
        elif exec_payloads:
            payload_name = exec_payloads[0]
        else:
            raise NotImplemented(
                "The specified payload is not implemented in this agent yet."
            )

        try:
            payload = self.client.modules.use("payload", payload_name)
        except TypeError:
            raise PayloadError("Received an invalid payload argument.")

        logger.info("Using %s payload", payload.fullname)
        argument = payload.missing_required[0]
        if argument == "CMD":
            payload[argument] = f"ping {self.lhost}"
        elif argument == "LHOST":
            payload[argument] = self.lhost
        else:
            raise NotImplemented("Payload configuration is not implemented")

        job = selected_module.execute(payload=payload)

    def _get_port(self, message: m.Message) -> int:
        """Returns the port to be used for the target."""
        if message.data.get("port") is not None:
            return int(message.data["port"])
        elif self.args.get("port") is not None:
            return int(str(self.args.get("port")))
        else:
            return DEFAULT_PORT

    def _prepare_target(self, message: m.Message) -> tuple[str, int]:
        """Prepare targets based on type, if a domain name is provided, port and protocol are collected
        from the config."""
        if (host := message.data.get("host")) is not None:
            port = self._get_port(message)
            return host, port
        elif (host := message.data.get("name")) is not None:
            port = self._get_port(message)
            return host, port
        elif (url := message.data.get("url")) is not None:
            parsed_url = urlparser.urlparse(url)
            host = parsed_url.netloc
            scheme = parsed_url.scheme
            port = SCHEME_TO_PORT.get(scheme) or DEFAULT_PORT
            return host, port
        else:
            raise NotImplemented("Received invalid target")


if __name__ == "__main__":
    logger.info("Starting Agent ...")
    MetasploitAgent.main()
