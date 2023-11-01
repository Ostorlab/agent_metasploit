"""Ostorlab Agent implementation for metasploit"""
import json
import logging
import socket
import time
from urllib import parse as urlparser

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import utils
from pymetasploit3 import msfrpc

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
MODULE_TIMEOUT = 180


class Error(Exception):
    """Base custom error class."""


class ArgumentError(Error):
    """Error when a required argument is missing"""


class ModuleError(Error):
    """Errors related to metasploit modules"""


class CheckError(Error):
    """Errors related to metasploit check method"""


class MetasploitAgent(
    agent.Agent, vuln_mixin.AgentReportVulnMixin, persist_mixin.AgentPersistMixin
):
    """Metasploit agent."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._client = utils.initialize_msf_rpc()
        self._cid = self._client.consoles.console().cid

    def process(self, message: m.Message) -> None:
        """Trigger Agent metasploit and emit findings

        Args:
            message: A message containing the path and the content of the file to be processed

        """
        module = self.args.get("module")
        if module is None:
            raise ArgumentError("Metasploit module must be specified.")

        vhost, rport = self._prepare_target(message)

        try:
            module_type, module_name = module.split("/", 1)
            selected_module = self._client.modules.use(module_type, module_name)
        except msfrpc.MsfRpcError as exc:
            raise ModuleError("Specified module does not exist") from exc

        logger.info("Selected metasploit module: %s", selected_module.modulename)
        selected_module = self._set_module_args(selected_module, vhost, rport)

        if module_type == "exploit":
            mode = "check"
            job = selected_module.check_exploit()
        elif module_type == "auxiliary":
            mode = "exploit"
            job = selected_module.execute()
        else:
            raise ArgumentError("Metasploit module should be exploit or auxiliary.")

        job_uuid = job["uuid"]
        started_timestamp = time.time()
        results = None
        while True:
            job_result = self._client.jobs.info_by_uuid(job_uuid)
            status = job_result["status"]
            if status == "completed":
                results = job_result["result"]
                break
            if status == "errored":
                logger.error("Encountered an unexpected error: %s", job_result["error"])
                break
            if time.time() - started_timestamp > MODULE_TIMEOUT:
                raise CheckError(f"Timeout while running job: {job_uuid}")
            time.sleep(5)

        if isinstance(results, dict) and results.get("code") == "safe":
            return

        technical_detail = f"Using `{module_type}` module `{module_name}`\n"
        technical_detail += f"Target: {vhost}\n"

        if isinstance(results, dict) and results.get("code") == "vulnerable":
            technical_detail += f'Message: {results["message"]}'
        else:
            console_output = self._client.consoles.console(
                self._cid
            ).run_module_with_output(selected_module, mode=mode)
            module_output = console_output.split("WORKSPACE => Ostorlab")[1]
            if "[-]" in module_output:
                return
            technical_detail += f"Message: {module_output}"

        entry = kb.KB.WEB_GENERIC
        entry.title = "Metasploit vulnerability detection"
        self.report_vulnerability(
            entry=entry,
            technical_detail=technical_detail,
            risk_rating=vuln_mixin.RiskRating.HIGH,
        )

    def _set_module_args(
        self, selected_module: msfrpc.MsfModule, vhost: str, rport: int
    ) -> msfrpc.MsfModule:
        rhost = socket.gethostbyname(vhost)
        if "RHOSTS" not in selected_module.required:
            raise ArgumentError(
                f"Argument not implemented, accepted args: {str(selected_module.required)}"
            )
        selected_module["RHOSTS"] = rhost
        if "VHOST" in selected_module.options:
            selected_module["VHOST"] = vhost
        if "RPORT" in selected_module.missing_required:
            selected_module["RPORT"] = rport

        msf_options = json.loads(self.args.get("options") or "[]")
        for arg in msf_options:
            arg_name = arg["name"]
            if arg_name in selected_module.options:
                selected_module[arg_name] = arg["value"]

        if len(selected_module.missing_required) > 0:
            raise ArgumentError(
                f"The following arguments are missing: {str(selected_module.missing_required)}"
            )

        return selected_module

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
            raise NotImplementedError


if __name__ == "__main__":
    logger.info("Starting Agent ...")
    MetasploitAgent.main()
