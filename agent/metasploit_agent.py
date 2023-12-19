"""Ostorlab Agent implementation for metasploit"""
import logging
import socket
import ipaddress
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

MODULE_TIMEOUT = 30
VULNERABLE_STATUSES = ["vulnerable", "appears"]
METASPLOIT_AGENT_KEY = b"agent_metasploit_asset"
REFERENCES = {
    "CVE": "https://nvd.nist.gov/vuln/detail/CVE-{ID}",
    "CWE": "https://cwe.mitre.org/data/definitions/{ID}.html",
    "EDB": "https://www.exploit-db.com/exploits/{ID}",
}


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
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        self._config = self.args.get("config", [])
        if self._config is None:
            raise ValueError("Metasploit module(s) must be specified.")

    def process(self, message: m.Message) -> None:
        """Trigger Agent metasploit and emit findings

        Args:
            message: A message containing the path and the content of the file to be processed

        """

        logger.info("processing message of selector : %s", message.selector)
        if self._is_target_already_processed(message) is True:
            return

        client = utils.connect_msfrpc()
        for entry in self._config:
            module = entry.get("module")
            options = entry.get("options") or []
            try:
                module_type, module_name = module.split("/", 1)
                selected_module = client.modules.use(module_type, module_name)
            except (msfrpc.MsfRpcError, ValueError):
                logger.error("Specified module %s does not exist", module)
                continue
            logger.info("Selected metasploit module: %s", selected_module.modulename)
            targets = utils.prepare_targets(message)
            for target in targets:
                vhost = target.host
                rport = target.port
                is_ssl = target.scheme == "https"
                try:
                    rhost = socket.gethostbyname(vhost)
                except socket.gaierror:
                    logger.warning("The specified target %s is not valid", vhost)
                    continue
                try:
                    module_instance = self._set_module_args(
                        selected_module, vhost, rhost, rport, is_ssl, options
                    )
                except ValueError as e:
                    logger.warning(
                        "Failed to set arguments for %s from %s",
                        selected_module.modulename,
                        e,
                    )
                    continue
                job = module_instance.check_exploit()
                if job.get("error") is True:
                    logger.error(
                        "Metasploit Error: %s", job.get("error_string", "Unknown Error")
                    )
                    continue

                job_uuid = job.get("uuid")
                if job_uuid is None:
                    continue

                results = self._get_job_results(client, job_uuid)

                if (
                    isinstance(results, dict)
                    and results.get("code") in VULNERABLE_STATUSES
                ):
                    technical_detail = f"Using `{module_instance.moduletype}` module `{module_instance.modulename}`\n"
                    technical_detail += f"Target: {vhost}:{rport}\n"
                    technical_detail += (
                        f'Message: \n```shell\n{results["message"]}\n```'
                    )

                    self._emit_results(module_instance, technical_detail)

        client.logout()

        self._mark_target_as_processed(message)
        logger.info("Done processing message of selector : %s", message.selector)

    def _is_target_already_processed(self, message: m.Message) -> bool:
        """Checks if the target has already been processed before, relies on the redis server."""
        if message.data.get("url") is not None or message.data.get("name") is not None:
            unicity_check_key = utils.get_unique_check_key(message)
            if unicity_check_key is None:
                return True
            return self.set_is_member(key=METASPLOIT_AGENT_KEY, value=unicity_check_key)

        if message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                return self.ip_network_exists(
                    key=METASPLOIT_AGENT_KEY, ip_range=addresses
                )
            return self.set_is_member(key=METASPLOIT_AGENT_KEY, value=host)
        logger.error("Unknown target %s", message)
        return True

    def _mark_target_as_processed(self, message: m.Message) -> None:
        """Mark the target as processed, relies on the redis server."""
        if message.data.get("url") is not None or message.data.get("name") is not None:
            unicity_check_key = utils.get_unique_check_key(message)
            if unicity_check_key is None:
                return

            self.set_add(METASPLOIT_AGENT_KEY, unicity_check_key)
        elif message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                self.add_ip_network(key=METASPLOIT_AGENT_KEY, ip_range=addresses)
            else:
                self.set_add(METASPLOIT_AGENT_KEY, host)
        else:
            logger.error("Unknown target %s", message)
            return

    def _get_job_results(
        self, client: msfrpc.MsfRpcClient, job_uuid: int
    ) -> dict[str, Any] | list[str] | None:
        results = None
        init_timestamp = time.time()
        while True:
            job_result = client.jobs.info_by_uuid(job_uuid)
            status = job_result.get("status")
            if status == "completed":
                results = job_result["result"]
                break
            if status == "errored":
                logger.warning("Module Error: %s", job_result["error"])
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
                if reference[0] == "URL":
                    msf_references[reference[1]] = reference[1]
                elif reference[0] in REFERENCES:
                    url = REFERENCES[reference[0]].format(ID=reference[1])
                    msf_references[url] = url
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
        rhost: str,
        rport: int,
        is_ssl: bool,
        options: list[dict[str, str]],
    ) -> msfrpc.MsfModule:
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
        if "RPORT" in selected_module.options:
            selected_module["RPORT"] = rport
        if "SSL" in selected_module.options:
            selected_module["SSL"] = is_ssl
        if "TARGETURI" in selected_module.missing_required:
            selected_module["TARGETURI"] = "/"
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
