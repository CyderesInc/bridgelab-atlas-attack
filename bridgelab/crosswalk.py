"""Bridge Crosswalk: ATLAS technique -> bridge condition -> ATT&CK v19 technique."""

import csv
import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path


@dataclass(frozen=True)
class CrosswalkEntry:
    atlas_technique_id: str
    atlas_technique_name: str
    bridge_condition: str
    attack_v19_technique_id: str
    attack_v19_technique_name: str
    attack_v19_tactic: str
    detection_opportunity: str
    log_source: str
    validated_environments: str = "AWS/LocalStack"


CROSSWALK_ENTRIES: list[CrosswalkEntry] = [
    CrosswalkEntry(
        atlas_technique_id="AML.T0080.001",
        atlas_technique_name="AI Agent Context Poisoning: Memory",
        bridge_condition=(
            "Poisoned memory entry instructs agent to add backup credentials; "
            "agent decides to use its own OAuth token to call IAM API"
        ),
        attack_v19_technique_id="T1098.001",
        attack_v19_technique_name="Account Manipulation: Additional Cloud Credentials",
        attack_v19_tactic="Persistence",
        detection_opportunity=(
            "IAM CreateAccessKey called by agent service principal outside scheduled rotation window"
        ),
        log_source="AWS CloudTrail / Azure Activity Log",
        validated_environments="AWS/LocalStack; Entra ID/Azure (live)",
    ),
    CrosswalkEntry(
        atlas_technique_id="AML.T0051",
        atlas_technique_name="LLM Prompt Injection",
        bridge_condition=(
            "Injected prompt in tool output instructs agent to call privileged API; "
            "agent uses its application access token for an out-of-scope resource"
        ),
        attack_v19_technique_id="T1550.001",
        attack_v19_technique_name="Use Alternate Authentication Material: Application Access Token",
        attack_v19_tactic="Lateral Movement",
        detection_opportunity=(
            "Agent service principal accesses resource outside its normal scope; "
            "token used for API not in agent's declared tool list"
        ),
        log_source="IdP audit log (Okta System Log / Entra Sign-in Log)",
        validated_environments="AWS/LocalStack (live); Entra ID/Azure (read-only proof only)",
    ),
    CrosswalkEntry(
        atlas_technique_id="AML.T0080",
        atlas_technique_name="AI Agent Context Poisoning",
        bridge_condition=(
            "Poisoned context causes agent to authenticate to a cloud resource "
            "outside its normal operating scope using its valid cloud identity"
        ),
        attack_v19_technique_id="T1078.004",
        attack_v19_technique_name="Valid Accounts: Cloud Accounts",
        attack_v19_tactic="Persistence",
        detection_opportunity=(
            "Agent cloud identity used to access resources with no prior access history; "
            "first-seen resource access by agent principal"
        ),
        log_source="Cloud audit log (CloudTrail / Activity Log / GCP Audit Log)",
    ),
    CrosswalkEntry(
        atlas_technique_id="AML.T0053",
        atlas_technique_name="AI Agent Tool Invocation",
        bridge_condition=(
            "Agent is manipulated into invoking its IAM management tool to "
            "attach an administrator policy to its own role"
        ),
        attack_v19_technique_id="T1098.003",
        attack_v19_technique_name="Account Manipulation: Additional Cloud Roles",
        attack_v19_tactic="Privilege Escalation",
        detection_opportunity=(
            "IAM role-policy attachment by agent principal that elevates its own permissions; "
            "self-escalation pattern (caller == target)"
        ),
        log_source="AWS CloudTrail IAM events / Microsoft Graph Audit Log (Entra ID directory roles)",
        validated_environments="AWS/LocalStack (live); Entra ID/Azure (read-only proof only)",
    ),
    CrosswalkEntry(
        atlas_technique_id="AML.T0110",
        atlas_technique_name="AI Agent Tool Poisoning",
        bridge_condition=(
            "Poisoned tool contains hidden code that reads the agent's credential files "
            "and exfiltrates them to an attacker-controlled endpoint"
        ),
        attack_v19_technique_id="T1552.001",
        attack_v19_technique_name="Unsecured Credentials: Credentials In Files",
        attack_v19_tactic="Credential Access",
        detection_opportunity=(
            "Agent process reads credential/config files outside its normal file access pattern; "
            "outbound connection to unknown endpoint immediately after credential file read"
        ),
        log_source="Host EDR / agent sandbox file-access log",
    ),
    CrosswalkEntry(
        atlas_technique_id="AML.T0083",
        atlas_technique_name="Credentials from AI Agent Configuration",
        bridge_condition=(
            "Adversary extracts stored OAuth tokens and API keys from agent configuration "
            "via prompt injection or configuration discovery"
        ),
        attack_v19_technique_id="T1528",
        attack_v19_technique_name="Steal Application Access Token",
        attack_v19_tactic="Credential Access",
        detection_opportunity=(
            "Agent's application token used from unexpected IP or user-agent; "
            "token replay from location inconsistent with agent's known infrastructure"
        ),
        log_source="IdP audit log / OAuth token introspection log",
    ),
    CrosswalkEntry(
        atlas_technique_id="AML.T0105",
        atlas_technique_name="Escape to Host",
        bridge_condition=(
            "Agent breaks out of its sandbox or container and accesses "
            "the host operating system's identity and credentials"
        ),
        attack_v19_technique_id="T1078.003",
        attack_v19_technique_name="Valid Accounts: Local Accounts",
        attack_v19_tactic="Privilege Escalation",
        detection_opportunity=(
            "Agent container or sandbox process accesses host credential stores; "
            "container escape indicators followed by local account authentication"
        ),
        log_source="Container runtime log (containerd/CRI-O) / host audit log",
    ),
    CrosswalkEntry(
        atlas_technique_id="AML.T0080.001",
        atlas_technique_name="AI Agent Context Poisoning: Memory",
        bridge_condition=(
            "Poisoned memory instructs agent to disable cloud audit logging "
            "before performing sensitive operations, using its legitimate admin access"
        ),
        attack_v19_technique_id="T1685.002",
        attack_v19_technique_name="Disable or Modify Tools: Disable or Modify Cloud Log",
        attack_v19_tactic="Defense Impairment",
        detection_opportunity=(
            "Audit-log config change by agent principal — CloudWatch Logs retention cut "
            "to the minimum (AWS) or a diagnostic setting deleted (Azure) by a non-human "
            "identity outside the logging-config change workflow"
        ),
        log_source="AWS CloudTrail management events / Azure Activity Log / SIEM alert on log-source gap",
        validated_environments="AWS/LocalStack (live); Entra ID/Azure (live)",
    ),
    CrosswalkEntry(
        atlas_technique_id="AML.T0104",
        atlas_technique_name="Publish Poisoned AI Agent Tool",
        bridge_condition=(
            "Tool from a compromised registry uses the agent's own cloud identity to "
            "create a brand-new backdoor identity (App Registration / IAM user) it "
            "controls, for persistent attacker access"
        ),
        attack_v19_technique_id="T1136.003",
        attack_v19_technique_name="Create Account: Cloud Account",
        attack_v19_tactic="Persistence",
        detection_opportunity=(
            "New App Registration / IAM user created by agent service principal; "
            "account creation by non-human identity outside provisioning workflow"
        ),
        log_source="AWS CloudTrail / Microsoft Graph Audit Log (Entra ID) / IdP provisioning log",
        validated_environments="AWS/LocalStack (code-complete, mock-verified); Entra ID/Azure (live)",
    ),
    CrosswalkEntry(
        atlas_technique_id="AML.T0053",
        atlas_technique_name="AI Agent Tool Invocation",
        bridge_condition=(
            "Agent is steered to read and exfiltrate sensitive data from cloud storage "
            "using its legitimate storage-reader credentials"
        ),
        attack_v19_technique_id="T1530",
        attack_v19_technique_name="Data from Cloud Storage",
        attack_v19_tactic="Collection",
        detection_opportunity=(
            "Agent principal accesses storage bucket or blob container outside its normal pattern; "
            "bulk read operations or access to buckets with no prior agent access history"
        ),
        log_source="S3 server access log / Azure Blob diagnostic log / GCP Cloud Audit Log",
        validated_environments="AWS/LocalStack (live); Entra ID/Azure (live)",
    ),
]


def export_json(entries: list[CrosswalkEntry], path: Path) -> None:
    """Export crosswalk entries to JSON file."""
    data = [asdict(e) for e in entries]
    path.write_text(json.dumps(data, indent=2) + "\n")


def export_csv(entries: list[CrosswalkEntry], path: Path) -> None:
    """Export crosswalk entries to CSV file."""
    fieldnames = [f.name for f in fields(CrosswalkEntry)]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(asdict(entry))


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Export Bridge Crosswalk")
    parser.add_argument("--output", default="output", help="Output directory")
    args = parser.parse_args()

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    export_json(CROSSWALK_ENTRIES, outdir / "bridge_crosswalk.json")
    export_csv(CROSSWALK_ENTRIES, outdir / "bridge_crosswalk.csv")
    print(f"Exported {len(CROSSWALK_ENTRIES)} crosswalk entries to {outdir}/")


if __name__ == "__main__":
    main()
