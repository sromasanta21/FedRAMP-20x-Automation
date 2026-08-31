#!/usr/bin/env python3
"""
ksi_validator.py
================
FedRAMP 20x Key Security Indicator (KSI) automated validation engine.

Scans a target Azure resource group (the simulated CSP environment) and
evaluates it against a subset of FedRAMP 20x KSI clusters:

  * KSI-SC  - System & Communications Protection
  * KSI-CNA - Cloud Native Architecture
  * KSI-MLA - Monitoring, Logging, & Auditing

Findings are rendered as:
  1. A human-readable summary table on the CLI (via `rich`).
  2. A machine-readable OSCAL-shaped Assessment Results JSON document,
     printed to stdout and written to `assessment_results.json`.

Authentication is handled by `DefaultAzureCredential`, which transparently
supports:
  * `az login` (Azure CLI credential) for local/interactive runs
  * A user-assigned or system-assigned Managed Identity when executed
    from inside Azure (e.g. Automation, DevOps agent, VM, Container App)
  * Environment-variable service principal credentials in CI/CD

Usage:
    python ksi_validator.py --resource-group rg-fedramp-target \
                             --workspace-name law-fedramp-20x-audit \
                             [--subscription-id <sub-id>] \
                             [--managed-identity-client-id <client-id>] \
                             [--output assessment_results.json]
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ADMIN_AND_UNENCRYPTED_PORTS = {"80", "22", "3389"}
OPEN_SOURCE_PREFIXES = {"0.0.0.0/0", "*", "internet", "any"}
SECURE_TLS_MINIMUM = "TLS1_2"
OSCAL_SCHEMA_VERSION = "1.1.2"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    INFO = "info"


class KSICluster(str, Enum):
    SC = "KSI-SC"
    CNA = "KSI-CNA"
    MLA = "KSI-MLA"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class KSIFinding:
    """A single control-check result produced by a KSI checker."""

    ksi_id: str                       # e.g. "KSI-SC-01"
    cluster: KSICluster
    title: str
    resource_name: str
    resource_id: str
    resource_type: str
    compliant: bool
    severity: Severity
    description: str
    remediation: str
    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    @property
    def status(self) -> str:
        return "PASS" if self.compliant else "FAIL"


# ---------------------------------------------------------------------------
# Authentication / SDK client context
# ---------------------------------------------------------------------------

class AzureContext:
    """
    Wraps DefaultAzureCredential + the ARM SDK clients required by the
    KSI checkers. DefaultAzureCredential tries credential sources in this
    order (relevant ones for this lab):
        EnvironmentCredential -> ManagedIdentityCredential ->
        AzureCliCredential -> ... (others)

    This means the exact same code path authenticates correctly whether
    it is run by an engineer who has done `az login` locally, or by the
    `id-ksi-scanner` user-assigned managed identity when executed inside
    Azure (e.g. an Automation Runbook or DevOps pipeline agent).
    """

    def __init__(self, subscription_id: str, managed_identity_client_id: Optional[str] = None):
        credential_kwargs = {}
        if managed_identity_client_id:
            # Pins DefaultAzureCredential's ManagedIdentityCredential to a
            # specific user-assigned identity (id-ksi-scanner) rather than
            # the system-assigned identity of the host.
            credential_kwargs["managed_identity_client_id"] = managed_identity_client_id

        self.credential = DefaultAzureCredential(**credential_kwargs)
        self.subscription_id = subscription_id

        self.storage_client = StorageManagementClient(self.credential, subscription_id)
        self.network_client = NetworkManagementClient(self.credential, subscription_id)
        self.monitor_client = MonitorManagementClient(self.credential, subscription_id)
        self.resource_client = ResourceManagementClient(self.credential, subscription_id)

    def verify_connectivity(self, resource_group: str) -> None:
        """Fail fast with a clear error if auth or the RG is invalid."""
        try:
            self.resource_client.resource_groups.get(resource_group)
        except ResourceNotFoundError as exc:
            raise SystemExit(
                f"[FATAL] Resource group '{resource_group}' was not found in "
                f"subscription '{self.subscription_id}'. Verify Terraform apply "
                f"succeeded and the name/subscription are correct."
            ) from exc
        except HttpResponseError as exc:
            raise SystemExit(
                f"[FATAL] Authentication or authorization failure while contacting "
                f"Azure Resource Manager: {exc.message}\n"
                f"Run 'az login' or verify the managed identity has 'Reader' on the "
                f"target resource group."
            ) from exc


# ---------------------------------------------------------------------------
# Base checker
# ---------------------------------------------------------------------------

class BaseKSIChecker:
    cluster: KSICluster

    def __init__(self, ctx: AzureContext, resource_group: str):
        self.ctx = ctx
        self.resource_group = resource_group
        self.findings: list[KSIFinding] = []

    def run(self) -> list[KSIFinding]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# KSI-SC : System & Communications Protection
# ---------------------------------------------------------------------------

class StorageProtectionChecker(BaseKSIChecker):
    """
    KSI-SC-01: All data-in-transit to storage services must be encrypted
               (HTTPS-only enforced).
    KSI-SC-02: Minimum negotiated TLS version must be 1.2 or higher.
    KSI-SC-03: Storage accounts should not be reachable over public network
               access unless explicitly justified (informational finding).
    """

    cluster = KSICluster.SC

    def run(self) -> list[KSIFinding]:
        accounts = list(
            self.ctx.storage_client.storage_accounts.list_by_resource_group(self.resource_group)
        )

        for account in accounts:
            self._check_https_enforced(account)
            self._check_tls_version(account)
            self._check_public_network_access(account)

        return self.findings

    def _check_https_enforced(self, account) -> None:
        https_only = bool(getattr(account, "enable_https_traffic_only", False))
        self.findings.append(
            KSIFinding(
                ksi_id="KSI-SC-01",
                cluster=self.cluster,
                title="HTTPS-Only Traffic Enforcement",
                resource_name=account.name,
                resource_id=account.id,
                resource_type="Microsoft.Storage/storageAccounts",
                compliant=https_only,
                severity=Severity.CRITICAL if not https_only else Severity.INFO,
                description=(
                    f"Storage account '{account.name}' "
                    + ("enforces HTTPS-only traffic." if https_only
                       else "allows plaintext HTTP traffic, exposing data-in-transit "
                            "to interception and tampering.")
                ),
                remediation=(
                    "N/A - already compliant." if https_only else
                    "Set 'supportsHttpsTrafficOnly' (enable_https_traffic_only) to "
                    "true on the storage account."
                ),
            )
        )

    def _check_tls_version(self, account) -> None:
        min_tls = getattr(account, "minimum_tls_version", None) or "UNKNOWN"
        compliant = min_tls == SECURE_TLS_MINIMUM or min_tls in {"TLS1_3"}
        self.findings.append(
            KSIFinding(
                ksi_id="KSI-SC-02",
                cluster=self.cluster,
                title="Minimum TLS Version >= 1.2",
                resource_name=account.name,
                resource_id=account.id,
                resource_type="Microsoft.Storage/storageAccounts",
                compliant=compliant,
                severity=Severity.HIGH if not compliant else Severity.INFO,
                description=(
                    f"Storage account '{account.name}' has minimum TLS version "
                    f"'{min_tls}'. "
                    + ("This meets the FedRAMP 20x cryptographic baseline."
                       if compliant else
                       "This is below the required TLS 1.2 baseline and permits "
                       "negotiation of deprecated, insecure protocol versions.")
                ),
                remediation=(
                    "N/A - already compliant." if compliant else
                    "Set 'minimumTlsVersion' (min_tls_version) to 'TLS1_2' or higher."
                ),
            )
        )

    def _check_public_network_access(self, account) -> None:
        public_access = getattr(account, "public_network_access", None)
        is_public = str(public_access).lower() == "enabled"
        self.findings.append(
            KSIFinding(
                ksi_id="KSI-SC-03",
                cluster=self.cluster,
                title="Public Network Access Restricted",
                resource_name=account.name,
                resource_id=account.id,
                resource_type="Microsoft.Storage/storageAccounts",
                compliant=not is_public,
                severity=Severity.MODERATE if is_public else Severity.INFO,
                description=(
                    f"Storage account '{account.name}' has public network access "
                    f"{'ENABLED' if is_public else 'disabled'}. "
                    + ("Data plane endpoints are reachable from the public internet."
                       if is_public else
                       "Data plane access is restricted to private/approved network paths.")
                ),
                remediation=(
                    "N/A - already compliant." if not is_public else
                    "Disable public network access and front the account with Private "
                    "Endpoints and/or virtual network service endpoints, restricting "
                    "'networkAcls.defaultAction' to Deny."
                ),
            )
        )


# ---------------------------------------------------------------------------
# KSI-CNA : Cloud Native Architecture
# ---------------------------------------------------------------------------

class NetworkArchitectureChecker(BaseKSIChecker):
    """
    KSI-CNA-01: Network Security Groups must not permit unrestricted
                inbound access ("0.0.0.0/0" / "*" / "Internet") on
                administrative or unencrypted ports (22, 3389, 80).
    KSI-CNA-02: NSGs should be associated with subnets (not left
                dangling/unassociated), enforcing segmentation by design.
    """

    cluster = KSICluster.CNA

    def run(self) -> list[KSIFinding]:
        nsgs = list(self.ctx.network_client.network_security_groups.list(self.resource_group))

        for nsg in nsgs:
            self._check_open_ingress_rules(nsg)
            self._check_subnet_association(nsg)

        return self.findings

    def _iter_effective_rules(self, nsg) -> Iterable:
        # Custom rules take precedence for review; default rules are
        # platform-managed and excluded from this specific check.
        return nsg.security_rules or []

    @staticmethod
    def _is_open_source(prefix: Optional[str]) -> bool:
        if not prefix:
            return False
        return prefix.strip().lower() in OPEN_SOURCE_PREFIXES

    @staticmethod
    def _touches_sensitive_port(port_range: Optional[str]) -> bool:
        if not port_range:
            return False
        port_range = port_range.strip()
        if port_range == "*":
            return True
        if "-" in port_range:
            try:
                low, high = (int(p) for p in port_range.split("-", 1))
            except ValueError:
                return False
            return any(low <= int(p) <= high for p in ADMIN_AND_UNENCRYPTED_PORTS)
        return port_range in ADMIN_AND_UNENCRYPTED_PORTS

    def _check_open_ingress_rules(self, nsg) -> None:
        offending_rules = []

        for rule in self._iter_effective_rules(nsg):
            if (rule.direction or "").lower() != "inbound":
                continue
            if (rule.access or "").lower() != "allow":
                continue

            source_prefixes = list(rule.source_address_prefixes or [])
            if rule.source_address_prefix:
                source_prefixes.append(rule.source_address_prefix)

            dest_ports = list(rule.destination_port_ranges or [])
            if rule.destination_port_range:
                dest_ports.append(rule.destination_port_range)

            open_source = any(self._is_open_source(p) for p in source_prefixes)
            sensitive_port = any(self._touches_sensitive_port(p) for p in dest_ports)

            if open_source and sensitive_port:
                offending_rules.append(
                    f"{rule.name} (ports: {','.join(dest_ports) or 'any'}, "
                    f"source: {','.join(source_prefixes) or 'any'})"
                )

        compliant = len(offending_rules) == 0
        self.findings.append(
            KSIFinding(
                ksi_id="KSI-CNA-01",
                cluster=self.cluster,
                title="No Unrestricted Ingress on Sensitive Ports",
                resource_name=nsg.name,
                resource_id=nsg.id,
                resource_type="Microsoft.Network/networkSecurityGroups",
                compliant=compliant,
                severity=Severity.CRITICAL if not compliant else Severity.INFO,
                description=(
                    f"NSG '{nsg.name}' "
                    + ("has no inbound rules permitting unrestricted access to "
                       "administrative or unencrypted ports."
                       if compliant else
                       "permits unrestricted inbound access (0.0.0.0/0 or '*') on "
                       "an administrative or unencrypted port. Offending rule(s): "
                       + "; ".join(offending_rules))
                ),
                remediation=(
                    "N/A - already compliant." if compliant else
                    "Restrict the source address prefix on the offending rule(s) to "
                    "specific CIDR ranges (e.g. a jump host or VPN gateway range), or "
                    "remove the rule and replace unencrypted port 80 with 443/TLS. "
                    "Consider Azure Bastion in place of open 22/3389."
                ),
            )
        )

    def _check_subnet_association(self, nsg) -> None:
        subnets = nsg.subnets or []
        associated = len(subnets) > 0
        self.findings.append(
            KSIFinding(
                ksi_id="KSI-CNA-02",
                cluster=self.cluster,
                title="NSG Associated With a Subnet (Segmentation Enforced)",
                resource_name=nsg.name,
                resource_id=nsg.id,
                resource_type="Microsoft.Network/networkSecurityGroups",
                compliant=associated,
                severity=Severity.LOW if not associated else Severity.INFO,
                description=(
                    f"NSG '{nsg.name}' is "
                    + (f"associated with {len(subnets)} subnet(s), actively enforcing "
                       "network segmentation." if associated else
                       "not associated with any subnet or NIC, so its rules are not "
                       "currently enforced anywhere.")
                ),
                remediation=(
                    "N/A - already compliant." if associated else
                    "Associate the NSG with the intended subnet(s) or NIC(s), or "
                    "remove it if it is orphaned/unused infrastructure."
                ),
            )
        )


# ---------------------------------------------------------------------------
# KSI-MLA : Monitoring, Logging, & Auditing
# ---------------------------------------------------------------------------

class MonitoringLoggingChecker(BaseKSIChecker):
    """
    KSI-MLA-01: In-scope resources must have an active Diagnostic Setting
                routing logs to the designated Log Analytics Workspace.
    """

    cluster = KSICluster.MLA

    def __init__(self, ctx: AzureContext, resource_group: str, workspace_id: Optional[str]):
        super().__init__(ctx, resource_group)
        self.workspace_id = (workspace_id or "").lower()

    def run(self) -> list[KSIFinding]:
        storage_accounts = list(
            self.ctx.storage_client.storage_accounts.list_by_resource_group(self.resource_group)
        )
        nsgs = list(self.ctx.network_client.network_security_groups.list(self.resource_group))

        for account in storage_accounts:
            blob_endpoint_id = f"{account.id}/blobServices/default"
            self._check_diagnostics(
                target_resource_id=blob_endpoint_id,
                resource_name=f"{account.name} (blob service)",
                resource_type="Microsoft.Storage/storageAccounts/blobServices",
            )

        for nsg in nsgs:
            self._check_diagnostics(
                target_resource_id=nsg.id,
                resource_name=nsg.name,
                resource_type="Microsoft.Network/networkSecurityGroups",
            )

        return self.findings

    def _check_diagnostics(self, target_resource_id: str, resource_name: str, resource_type: str) -> None:
        wired_to_workspace = False
        setting_names: list[str] = []

        try:
            settings = self.ctx.monitor_client.diagnostic_settings.list(target_resource_id)
            for setting in settings:
                setting_names.append(setting.name)
                ws_id = (getattr(setting, "workspace_id", None) or "").lower()
                if ws_id and (not self.workspace_id or ws_id == self.workspace_id):
                    wired_to_workspace = True
        except HttpResponseError:
            # Resource type may not support diagnostic settings at this
            # scope, or the identity lacks read access - treat as non-compliant
            # rather than raising, so the scan can complete.
            wired_to_workspace = False

        self.findings.append(
            KSIFinding(
                ksi_id="KSI-MLA-01",
                cluster=self.cluster,
                title="Diagnostic Logging Routed to Central Workspace",
                resource_name=resource_name,
                resource_id=target_resource_id,
                resource_type=resource_type,
                compliant=wired_to_workspace,
                severity=Severity.HIGH if not wired_to_workspace else Severity.INFO,
                description=(
                    f"Resource '{resource_name}' "
                    + (f"has active diagnostic setting(s) [{', '.join(setting_names)}] "
                       "routing audit logs to the designated Log Analytics Workspace."
                       if wired_to_workspace else
                       "has no diagnostic setting routing logs to the designated Log "
                       "Analytics Workspace, creating a gap in the audit trail.")
                ),
                remediation=(
                    "N/A - already compliant." if wired_to_workspace else
                    "Create a Diagnostic Setting on this resource that sends relevant "
                    "log categories and metrics to the Log Analytics Workspace "
                    "(law-fedramp-20x-audit)."
                ),
            )
        )


# ---------------------------------------------------------------------------
# OSCAL Assessment Results builder
# ---------------------------------------------------------------------------

class OSCALResultsBuilder:
    """
    Serializes KSIFinding objects into an OSCAL-shaped Assessment Results
    document (observations + findings), suitable for ingestion into a
    FedRAMP 20x continuous-monitoring evidence pipeline.

    This is a pragmatic subset of the full OSCAL assessment-results model
    (oscal-version 1.1.2) - it captures observations, findings, subjects,
    and related metadata without requiring the full OSCAL Python library.
    """

    def __init__(self, subscription_id: str, resource_group: str):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.run_uuid = str(uuid.uuid4())
        self.generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def build(self, findings: list[KSIFinding]) -> dict:
        observations = [self._to_observation(f) for f in findings]
        oscal_findings = [self._to_finding(f) for f in findings]

        total = len(findings)
        passed = sum(1 for f in findings if f.compliant)
        failed = total - passed

        by_cluster: dict[str, dict] = {}
        for f in findings:
            bucket = by_cluster.setdefault(
                f.cluster.value, {"total": 0, "passed": 0, "failed": 0}
            )
            bucket["total"] += 1
            bucket["passed"] += 1 if f.compliant else 0
            bucket["failed"] += 0 if f.compliant else 1

        document = {
            "assessment-results": {
                "uuid": self.run_uuid,
                "metadata": {
                    "title": "FedRAMP 20x KSI Automated Assessment Results",
                    "last-modified": self.generated_at,
                    "version": "1.0.0",
                    "oscal-version": OSCAL_SCHEMA_VERSION,
                    "parties": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "type": "organization",
                            "name": "Automated KSI Validation Engine (ksi_validator.py)",
                        }
                    ],
                },
                "import-ap": {
                    "href": "#fedramp-20x-ksi-baseline"
                },
                "local-definitions": {
                    "assessment-assets": {
                        "assessment-platforms": [
                            {
                                "uuid": str(uuid.uuid4()),
                                "title": "Python KSI Validation Engine",
                                "props": [
                                    {"name": "component-type", "value": "validation-engine"},
                                    {"name": "language", "value": "python"},
                                ],
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "uuid": self.run_uuid,
                        "title": "Automated KSI Cluster Evaluation",
                        "description": (
                            "Automated evaluation of KSI-SC, KSI-CNA, and KSI-MLA "
                            f"clusters against resource group '{self.resource_group}' "
                            f"in subscription '{self.subscription_id}'."
                        ),
                        "start": self.generated_at,
                        "end": self.generated_at,
                        "reviewed-controls": {
                            "control-selections": [
                                {"description": "KSI-SC, KSI-CNA, KSI-MLA control clusters"}
                            ]
                        },
                        "props": [
                            {"name": "total-checks", "value": str(total)},
                            {"name": "passed-checks", "value": str(passed)},
                            {"name": "failed-checks", "value": str(failed)},
                            {
                                "name": "compliance-percentage",
                                "value": f"{(passed / total * 100):.1f}" if total else "0.0",
                            },
                        ],
                        "observations": observations,
                        "findings": oscal_findings,
                    }
                ],
                "back-matter": {
                    "resources": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "title": "Cluster Summary",
                            "props": [
                                {"name": f"{cluster}-total", "value": str(v["total"])}
                                for cluster, v in by_cluster.items()
                            ]
                            + [
                                {"name": f"{cluster}-passed", "value": str(v["passed"])}
                                for cluster, v in by_cluster.items()
                            ]
                            + [
                                {"name": f"{cluster}-failed", "value": str(v["failed"])}
                                for cluster, v in by_cluster.items()
                            ],
                        }
                    ]
                },
            }
        }
        return document

    @staticmethod
    def _to_observation(f: KSIFinding) -> dict:
        return {
            "uuid": f.uuid,
            "title": f.title,
            "description": f.description,
            "methods": ["TEST-AUTOMATED"],
            "collected": f.timestamp,
            "subjects": [
                {
                    "subject-uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f.resource_id)),
                    "type": "component",
                    "title": f.resource_name,
                    "props": [
                        {"name": "resource-id", "value": f.resource_id},
                        {"name": "resource-type", "value": f.resource_type},
                    ],
                }
            ],
            "props": [
                {"name": "ksi-id", "value": f.ksi_id},
                {"name": "ksi-cluster", "value": f.cluster.value},
                {"name": "status", "value": f.status},
                {"name": "severity", "value": f.severity.value},
            ],
        }

    @staticmethod
    def _to_finding(f: KSIFinding) -> dict:
        return {
            "uuid": str(uuid.uuid4()),
            "title": f"{f.ksi_id}: {f.title}",
            "description": f.description,
            "related-observations": [{"observation-uuid": f.uuid}],
            "target": {
                "type": "objective-id",
                "target-id": f.ksi_id,
                "status": {
                    "state": "satisfied" if f.compliant else "not-satisfied"
                },
            },
            "props": [
                {"name": "ksi-cluster", "value": f.cluster.value},
                {"name": "severity", "value": f.severity.value},
                {"name": "resource-name", "value": f.resource_name},
                {"name": "resource-id", "value": f.resource_id},
            ],
            "remarks": f.remediation,
        }


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------

class CLIReporter:
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_banner(self, subscription_id: str, resource_group: str) -> None:
        self.console.print(
            Panel.fit(
                f"[bold cyan]FedRAMP 20x KSI Automated Validation Engine[/bold cyan]\n"
                f"Subscription: [yellow]{subscription_id}[/yellow]\n"
                f"Target Resource Group: [yellow]{resource_group}[/yellow]",
                border_style="cyan",
            )
        )

    def render_findings_table(self, findings: list[KSIFinding]) -> None:
        table = Table(title="KSI Assessment Findings", box=box.SQUARE_DOUBLE_HEAD, show_lines=False)
        table.add_column("KSI ID", style="bold")
        table.add_column("Cluster")
        table.add_column("Resource")
        table.add_column("Check")
        table.add_column("Status", justify="center")
        table.add_column("Severity")

        for f in sorted(findings, key=lambda x: (x.cluster.value, x.ksi_id, x.resource_name)):
            status_style = "bold green" if f.compliant else "bold red"
            severity_style = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "red",
                Severity.MODERATE: "yellow",
                Severity.LOW: "cyan",
                Severity.INFO: "dim",
            }[f.severity]

            table.add_row(
                f.ksi_id,
                f.cluster.value,
                f.resource_name,
                f.title,
                f"[{status_style}]{f.status}[/{status_style}]",
                f"[{severity_style}]{f.severity.value.upper()}[/{severity_style}]",
            )

        self.console.print(table)

    def render_summary(self, findings: list[KSIFinding]) -> None:
        total = len(findings)
        passed = sum(1 for f in findings if f.compliant)
        failed = total - passed
        pct = (passed / total * 100) if total else 0.0

        summary_table = Table(title="Compliance Summary", box=box.SIMPLE_HEAVY)
        summary_table.add_column("Cluster")
        summary_table.add_column("Total", justify="right")
        summary_table.add_column("Passed", justify="right")
        summary_table.add_column("Failed", justify="right")

        by_cluster: dict[str, dict] = {}
        for f in findings:
            bucket = by_cluster.setdefault(f.cluster.value, {"total": 0, "passed": 0, "failed": 0})
            bucket["total"] += 1
            bucket["passed"] += 1 if f.compliant else 0
            bucket["failed"] += 0 if f.compliant else 1

        for cluster, stats in sorted(by_cluster.items()):
            summary_table.add_row(
                cluster, str(stats["total"]), str(stats["passed"]), str(stats["failed"])
            )

        self.console.print(summary_table)

        overall_style = "bold green" if failed == 0 else "bold red"
        self.console.print(
            Panel.fit(
                f"Total Checks: [bold]{total}[/bold]   "
                f"Passed: [bold green]{passed}[/bold green]   "
                f"Failed: [bold red]{failed}[/bold red]   "
                f"Compliance: [{overall_style}]{pct:.1f}%[/{overall_style}]",
                title="Overall Result",
                border_style=overall_style.split()[-1],
            )
        )

    def render_non_compliant_detail(self, findings: list[KSIFinding]) -> None:
        non_compliant = [f for f in findings if not f.compliant]
        if not non_compliant:
            self.console.print("[bold green]No non-compliant findings detected.[/bold green]")
            return

        self.console.print(Panel.fit("[bold red]Non-Compliant Finding Detail[/bold red]"))
        for f in non_compliant:
            self.console.print(
                f"[bold red]● {f.ksi_id}[/bold red] - {f.title} on "
                f"[yellow]{f.resource_name}[/yellow]"
            )
            self.console.print(f"    Description : {f.description}")
            self.console.print(f"    Remediation : {f.remediation}\n")


# ---------------------------------------------------------------------------
# Orchestration engine
# ---------------------------------------------------------------------------

class KSIValidationEngine:
    def __init__(
        self,
        subscription_id: str,
        resource_group: str,
        workspace_resource_id: Optional[str] = None,
        managed_identity_client_id: Optional[str] = None,
    ):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.ctx = AzureContext(subscription_id, managed_identity_client_id)
        self.workspace_resource_id = workspace_resource_id
        self.reporter = CLIReporter()

    def run(self) -> list[KSIFinding]:
        self.reporter.render_banner(self.subscription_id, self.resource_group)
        self.ctx.verify_connectivity(self.resource_group)

        checkers: list[BaseKSIChecker] = [
            StorageProtectionChecker(self.ctx, self.resource_group),
            NetworkArchitectureChecker(self.ctx, self.resource_group),
            MonitoringLoggingChecker(self.ctx, self.resource_group, self.workspace_resource_id),
        ]

        all_findings: list[KSIFinding] = []
        for checker in checkers:
            with self.reporter.console.status(f"[cyan]Running {checker.cluster.value} checks..."):
                all_findings.extend(checker.run())

        return all_findings

    def report(self, findings: list[KSIFinding], output_path: str) -> dict:
        self.reporter.render_findings_table(findings)
        self.reporter.render_summary(findings)
        self.reporter.render_non_compliant_detail(findings)

        builder = OSCALResultsBuilder(self.subscription_id, self.resource_group)
        oscal_document = builder.build(findings)

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(oscal_document, fh, indent=2)

        self.reporter.console.print(
            f"\n[bold]OSCAL evidence package written to:[/bold] [underline]{output_path}[/underline]"
        )

        return oscal_document


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def resolve_workspace_resource_id(
    ctx: AzureContext, resource_group: str, workspace_name: Optional[str]
) -> Optional[str]:
    """Look up the full ARM resource ID of the Log Analytics Workspace by
    name so KSI-MLA checks can match diagnostic settings against it."""
    if not workspace_name:
        return None

    for rg in [resource_group]:
        try:
            result = ctx.resource_client.resources.get_by_id(
                resource_id=(
                    f"/subscriptions/{ctx.subscription_id}/resourceGroups/{rg}"
                    f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
                ),
                api_version="2022-10-01",
            )
            return result.id
        except HttpResponseError:
            continue
    return None


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="FedRAMP 20x KSI Automated Validation Engine"
    )
    parser.add_argument(
        "--resource-group",
        default=os.environ.get("KSI_TARGET_RESOURCE_GROUP", "rg-fedramp-target"),
        help="Target CSP resource group to scan (default: rg-fedramp-target).",
    )
    parser.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID"),
        help="Azure subscription ID. Falls back to AZURE_SUBSCRIPTION_ID env var.",
    )
    parser.add_argument(
        "--workspace-name",
        default=os.environ.get("KSI_LAW_WORKSPACE_NAME", "law-fedramp-20x-audit"),
        help="Log Analytics Workspace name used for KSI-MLA checks.",
    )
    parser.add_argument(
        "--managed-identity-client-id",
        default=os.environ.get("KSI_SCANNER_MI_CLIENT_ID"),
        help="Client ID of a user-assigned managed identity (id-ksi-scanner) to "
             "authenticate with when running inside Azure. Omit for local `az login`.",
    )
    parser.add_argument(
        "--output",
        default="assessment_results.json",
        help="Path to write the OSCAL JSON evidence package (default: assessment_results.json).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    if not args.subscription_id:
        print(
            "[FATAL] No subscription ID provided. Pass --subscription-id or set "
            "AZURE_SUBSCRIPTION_ID, or run 'az account set --subscription <id>' and "
            "export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv).",
            file=sys.stderr,
        )
        return 2

    engine = KSIValidationEngine(
        subscription_id=args.subscription_id,
        resource_group=args.resource_group,
        managed_identity_client_id=args.managed_identity_client_id,
    )

    workspace_resource_id = resolve_workspace_resource_id(
        engine.ctx, args.resource_group, args.workspace_name
    )
    engine.workspace_resource_id = workspace_resource_id

    findings = engine.run()
    oscal_document = engine.report(findings, args.output)

    # Also emit the OSCAL JSON to stdout for pipeline capture, separated
    # from the rich CLI output which is written to the console (stderr-safe).
    print(json.dumps(oscal_document, indent=2))

    failed = sum(1 for f in findings if not f.compliant)
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
