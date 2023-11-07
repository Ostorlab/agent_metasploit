"""Ostorlab Agent implementation for metasploit"""
import logging
import socket
import time
from typing import Any

import timeout_decorator
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

MODULE_TIMEOUT = 180


class Error(Exception):
    """Base custom error class."""


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
        module = self.args.get("module")
        if module is None:
            raise ValueError("Metasploit module must be specified.")
        try:
            module_type, module_name = module.split("/", 1)
            self.selected_module = self._client.modules.use(module_type, module_name)
        except msfrpc.MsfRpcError as exc:
            raise ModuleError("Specified module does not exist") from exc
        logger.info("Selected metasploit module: %s", self.selected_module.modulename)

    def process(self, message: m.Message) -> None:
        """Trigger Agent metasploit and emit findings

        Args:
            message: A message containing the path and the content of the file to be processed

        """
        vhost, rport = utils.prepare_target(message)
        module_instance = self._set_module_args(self.selected_module, vhost, rport)
        if module_instance.moduletype == "exploit":
            job = module_instance.check_exploit()
        elif module_instance.moduletype == "auxiliary":
            job = module_instance.execute()
        else:
            raise ValueError(
                f"{module_instance.moduletype} module type is not implemented"
            )
        job_uuid = job["uuid"]
        results = self._get_job_results(job_uuid)

        if isinstance(results, dict) and results.get("code") == "safe":
            return

        target = module_instance.runoptions.get(
            "VHOST"
        ) or module_instance.runoptions.get("RHOSTS")
        technical_detail = f"Using `{module_instance.moduletype}` module `{module_instance.modulename}`\n"
        technical_detail += f"Target: {target}\n"

        if isinstance(results, dict) and results.get("code") == "vulnerable":
            technical_detail += f'Message: \n```{results["message"]}```'
        else:
            console_output = self._client.consoles.console(
                self._cid
            ).run_module_with_output(module_instance)
            module_output = console_output.split("WORKSPACE => Ostorlab")[1]
            if "[-]" in module_output:
                return
            technical_detail += f"Message: \n```{module_output}```"

        self._emit_results(module_instance, technical_detail)

    @timeout_decorator.timeout(MODULE_TIMEOUT, timeout_exception=ModuleError)  # type: ignore
    def _get_job_results(self, job_uuid: int) -> dict[str, Any] | list[str] | None:
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
            time.sleep(10)

        return results

    def _emit_results(
        self, module_instance: msfrpc.MsfModule, technical_detail: str
    ) -> None:
        entry_title = module_instance.name or "Metasploit generic vulnerability entry"
        msf_references = {}
        for reference in module_instance.references:
            if isinstance(reference, list) and len(reference) == 2:
                msf_references[reference[0]] = reference[1]
        entry = kb.Entry(
            title=entry_title,
            risk_rating="HIGH",
            short_description=module_instance.description,
            description=module_instance.description,
            references=msf_references,
            recommendation=(
                "- Make sure to install the latest security patches from software vendor "
                "- Update to the latest software version"
            ),
            security_issue=True,
            privacy_issue=False,
            has_public_exploit=False,
            targeted_by_malware=False,
            targeted_by_ransomware=False,
            targeted_by_nation_state=False,
        )
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
            raise ValueError(
                f"Argument not implemented, accepted args: {str(selected_module.required)}"
            )
        selected_module["RHOSTS"] = rhost
        if "VHOST" in selected_module.options:
            selected_module["VHOST"] = vhost
        if "RPORT" in selected_module.missing_required:
            selected_module["RPORT"] = rport

        msf_options = self.args.get("options") or []
        for arg in msf_options:
            arg_name = arg["name"]
            if arg_name in selected_module.options:
                selected_module[arg_name] = arg["value"]

        if len(selected_module.missing_required) > 0:
            raise ValueError(
                f"The following arguments are missing: {str(selected_module.missing_required)}"
            )

        return selected_module


if __name__ == "__main__":
    logger.info("Starting Agent...")
    MetasploitAgent.main()
