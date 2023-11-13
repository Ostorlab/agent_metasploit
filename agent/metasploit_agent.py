"""Ostorlab Agent implementation for metasploit"""
import logging
import socket
import time
from typing import Any

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

MODULE_TIMEOUT = 300
WORKSPACE_ARG = "WORKSPACE => Ostorlab"
MSF_SAFE_INDICATOR = "[-]"
MSF_UNKNOWN_INDICATOR = "Cannot reliably check exploitability"


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
        self.config = self.args.get("config", [])
        if self.config is None:
            raise ValueError("Metasploit module(s) must be specified.")

    def process(self, message: m.Message) -> None:
        """Trigger Agent metasploit and emit findings

        Args:
            message: A message containing the path and the content of the file to be processed

        """
        utils.start_msfrpcd()
        client = utils.connect_msfrpc()
        cid = client.consoles.console().cid
        for entry in self.config:
            module = entry.get("module")
            options = entry.get("options") or []
            try:
                module_type, module_name = module.split("/", 1)
                selected_module = client.modules.use(module_type, module_name)
            except (msfrpc.MsfRpcError, ValueError) as exc:
                raise ModuleError("Specified module does not exist") from exc
            logger.info("Selected metasploit module: %s", selected_module.modulename)
            vhost, rport = utils.prepare_target(message)
            module_instance = self._set_module_args(
                selected_module, vhost, rport, options
            )
            if module_instance.moduletype == "exploit":
                job = module_instance.check_exploit()
            elif module_instance.moduletype == "auxiliary":
                job = module_instance.execute()
            else:
                raise ValueError(
                    f"{module_instance.moduletype} module type is not implemented"
                )
            job_uuid = job["uuid"]
            results = self._get_job_results(client, job_uuid)

            if isinstance(results, dict) and results.get("code") in ["safe", "unknown"]:
                return

            target = (
                module_instance.runoptions.get("VHOST")
                or module_instance.runoptions.get("RHOSTS")
                or module_instance.runoptions.get("DOMAIN")
            )
            technical_detail = f"Using `{module_instance.moduletype}` module `{module_instance.modulename}`\n"
            technical_detail += f"Target: {target}\n"

            if isinstance(results, dict) and results.get("code") == "vulnerable":
                technical_detail += f'Message: \n```{results["message"]}```'
            else:
                console_output = client.consoles.console(cid).run_module_with_output(
                    module_instance
                )
                try:
                    module_output = console_output.split(WORKSPACE_ARG)[1]
                except IndexError:
                    logger.error("Unexpected console output:\n %s", console_output)
                    return None
                if MSF_SAFE_INDICATOR in module_output:
                    return
                if MSF_UNKNOWN_INDICATOR in module_output:
                    return
                technical_detail += f"Message: \n```{module_output}```"

            self._emit_results(module_instance, technical_detail)
            client.logout()

    def _get_job_results(
        self, client: msfrpc.MsfRpcClient, job_uuid: int
    ) -> dict[str, Any] | list[str] | None:
        results = None
        init_timestamp = time.time()
        while True:
            job_result = client.jobs.info_by_uuid(job_uuid)
            status = job_result["status"]
            if status == "completed":
                results = job_result["result"]
                break
            if status == "errored":
                logger.error("Encountered an unexpected error: %s", job_result["error"])
                break
            if time.time() - init_timestamp > MODULE_TIMEOUT:
                logger.error("Metasploit job %s timed out", job_uuid)
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
                "- Make sure to install the latest security patches from software vendor \n"
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
        self,
        selected_module: msfrpc.MsfModule,
        vhost: str,
        rport: int,
        options: list[dict[str, str]],
    ) -> msfrpc.MsfModule:
        rhost = socket.gethostbyname(vhost)
        if "RHOSTS" in selected_module.required:
            selected_module["RHOSTS"] = rhost
        elif "DOMAIN" in selected_module.required:
            selected_module["DOMAIN"] = rhost
        else:
            raise ValueError(
                f"Argument not implemented, accepted args: {str(selected_module.required)}"
            )
        if "VHOST" in selected_module.options:
            selected_module["VHOST"] = vhost
        if "RPORT" in selected_module.missing_required:
            selected_module["RPORT"] = rport

        for arg in options:
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
