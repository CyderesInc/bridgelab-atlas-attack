# Entra ID / Azure setup for BridgeLab

This is the second live identity/cloud pairing alongside the default
Keycloak + LocalStack path — Microsoft Entra ID issuing the agent's token,
a real Azure tenant absorbing the escalation. It targets **your own
dedicated, non-production test tenant** — never a real organization's
production tenant. As a safety rule, a live/interactive run always keeps
the destructive step in LocalStack; the Entra→Azure destructive path is
only ever run deliberately, off-stage, to capture the fallback recording.

## What to register in your test tenant

You need two things, both throwaway, both scoped to this lab only:

1. **Agent identity** — an App Registration representing `bridgelab-agent`.
   - Create a client secret for it.
   - Grant it the Graph application permission **`Application.ReadWrite.OwnedBy`**
     (not `Application.ReadWrite.All`) — this only lets it manage **Application**
     objects it owns, which is enough for the demo and keeps the blast radius
     to the one target app below. Grant admin consent for that permission.

2. **Target/victim App Registration** — a second, separate App Registration,
   representing `bridgelab-backup-app`. `AzureIAMTool` calls the Graph
   `/applications/{id}/addPassword` action against it, so ownership has to be
   on the **Application** object, not its Service Principal:

   ```bash
   # Object ID of bridgelab-agent's *Service Principal* (Enterprise
   # Applications blade), not its Application/App-registration object ID:
   az ad sp show --id <bridgelab-agent's Application (client) ID> --query id -o tsv

   # Add it as an owner of the target Application object:
   az ad app owner add --id <target app's Application object ID> \
     --owner-object-id <bridgelab-agent service principal object ID from above>
   ```

   Three different GUIDs are in play for "the same app" — mixing them up is
   the most common way this breaks:
   - **Application (client) ID** — `appId`, used nowhere in this flow.
   - **Application object ID** — the App registration's own object ID (App
     registrations blade → Overview). This is what `AZURE_TARGET_APP_ID`
     wants, and what `az ad app owner add --id` targets.
   - **Service Principal object ID** — the Enterprise Application's object ID
     (Enterprise applications blade → Overview, *not* App registrations).
     This is what `--owner-object-id` wants for the agent.

   `az ad app owner add`'s Portal equivalent (App registration → Owners →
   Add owners) often won't let you search for a service principal by name —
   the CLI/Graph route above is the reliable one.

## Second technique: privilege escalation (`--technique additional-roles`)

This one is **read-only against Azure, always** — there is no
`--confirm-destructive` path for it, by design (see below), unlike the
credentials technique above.

3. **Extra permission on the agent's app registration** — grant
   **`RoleManagement.ReadWrite.Directory`** in addition to
   `Application.ReadWrite.OwnedBy`, and admin-consent it. Think carefully
   before granting this even on a disposable test tenant: unlike
   `Application.ReadWrite.OwnedBy`, Graph does not scope this down to owned
   objects — an app with it can assign *any* directory role to *any*
   principal, including Global Administrator. Because of that,
   `AzureIAMTool` has no code path that ever performs a real directory-role
   assignment — the live path only ever calls the read-only
   `roleManagement/directory/roleAssignments` list, regardless of
   `--confirm-destructive`. If you'd rather not grant this permission at
   all, skip it — `--technique additional-roles --cloud azure` will just
   403 on the read, which is a fine (if less satisfying) way to show the
   permission boundary without ever holding the broader grant.

`ENTRA_AGENT_SP_OBJECT_ID` in `.env` is the agent's own Service Principal
object ID — the same value you already looked up via `az ad sp show` in
step 2 above. Self-escalation means caller and target are the same principal.

## Third technique: lateral movement (`--technique out-of-scope-access`)

This one needs **no new permission grant** — it reuses the same
`RoleManagement.ReadWrite.Directory` read path as the technique above,
pointed at a different principal. The demonstration is that the agent's
*token* doesn't know or care which principal it's asked about; only the
agent's declared tool list is supposed to constrain that, and a poisoned
tool output can steer it elsewhere.

`ENTRA_OUT_OF_SCOPE_PRINCIPAL_ID` in `.env` is any other principal's object
ID in your test tenant — your own user account, a spare service principal,
anything other than `bridgelab-agent`'s own SP. If you skipped granting
`RoleManagement.ReadWrite.Directory` above, this technique will just 403
against Azure too, for the same reason. There is no destructive path to
speak of here at all — `AzureIAMTool` has no write action for this
technique, live or mock.

## Fourth technique: data collection (`--technique data-collection`)

This one is **fully live, always** — unlike the two techniques above,
there is no read-only cap and no `--confirm-destructive` behavior to speak
of, because the permission it needs is container-scoped (not tenant-wide
like `RoleManagement.ReadWrite.Directory`) and the technique's real action
already is a read. It also needs a **Storage-scoped token**
(`https://storage.azure.com/.default`), not the Graph-scoped token every
other technique uses — same `bridgelab-agent` client credentials, a
different resource. No extra Graph permission is needed for this one.

4. **A throwaway Storage Account + container**, with a couple of sample
   blobs, and the agent's SP granted **`Storage Blob Data Reader`** scoped
   to that container:

   ```bash
   # Create a disposable Storage Account (StorageV2, any region) and container
   az storage account create --name <storage-account-name> \
     --resource-group <your-resource-group> --sku Standard_LRS
   az storage container create --name bridgelab-sensitive-data \
     --account-name <storage-account-name> --auth-mode login

   # Upload sample blobs, mirroring init-aws.sh's three LocalStack objects.
   # Use --file, not `--data -`: piping to `--data -` is unreliable across
   # az CLI versions/shells and can silently upload the literal "-"
   # argument as 1-byte blob content instead of reading stdin.
   printf '{"secret": "this-is-sensitive-data"}' > /tmp/pii-records.json
   az storage blob upload --account-name <storage-account-name> \
     --container-name bridgelab-sensitive-data --name pii/records.json \
     --file /tmp/pii-records.json --auth-mode login

   printf '{"account": "0000-1111-2222", "balance": "48210.55"}' > /tmp/financial-statement.json
   az storage blob upload --account-name <storage-account-name> \
     --container-name bridgelab-sensitive-data --name financial/statement.json \
     --file /tmp/financial-statement.json --auth-mode login

   printf '{"api_key": "sk-live-do-not-use-in-production"}' > /tmp/credentials-api-keys.json
   az storage blob upload --account-name <storage-account-name> \
     --container-name bridgelab-sensitive-data --name credentials/api_keys.json \
     --file /tmp/credentials-api-keys.json --auth-mode login

   rm /tmp/pii-records.json /tmp/financial-statement.json /tmp/credentials-api-keys.json

   # Grant bridgelab-agent's SP Storage Blob Data Reader, scoped to just
   # this container (not the whole storage account)
   az role assignment create \
     --assignee <bridgelab-agent's Application (client) ID> \
     --role "Storage Blob Data Reader" \
     --scope "/subscriptions/<sub-id>/resourceGroups/<your-resource-group>/providers/Microsoft.Storage/storageAccounts/<storage-account-name>/blobServices/default/containers/bridgelab-sensitive-data"
   ```

   `AZURE_STORAGE_ACCOUNT` in `.env` is `<storage-account-name>` above;
   `AZURE_STORAGE_CONTAINER` defaults to `bridgelab-sensitive-data` to
   match the LocalStack bucket name, but any container name works as long
   as it matches what you created and scoped the role assignment to.

## Fifth technique: account creation (`--technique create-account`)

This is T1136.003 — the agent using its own token to mint a **brand-new
backdoor identity** (an Azure App Registration), distinct from adding a
credential to an existing app (`additional-credentials`). Like
`additional-credentials`, it is gated behind `--confirm-destructive`:
without the flag it runs read-only (lists existing applications); with it,
`AzureIAMTool` creates the App Registration and then **immediately deletes
it** (auto-cleanup), so both the "Add application" and "Delete application"
events land in the Entra audit log with no persistent backdoor left in the
tenant to rotate later.

5. **Extra permission on the agent's app registration** — grant
   **`Application.ReadWrite.All`** (not just the scoped
   `Application.ReadWrite.OwnedBy` the default technique uses), and
   admin-consent it. Creating a *new* application is a directory-wide
   action Graph will not let an app perform under the OwnedBy grant, which
   only covers apps it already owns. This is a genuinely powerful grant —
   treat it the same way as `RoleManagement.ReadWrite.Directory` above. If
   you'd rather not grant it, skip it and run against LocalStack instead
   (`--technique create-account --cloud localstack`), which creates a
   throwaway IAM user in the sandbox with no real blast radius. It uses the
   same Graph-scoped token (`https://graph.microsoft.com/.default`) as the
   other App Registration techniques — no new token resource.

   **Replication-lag note.** Graph is eventually consistent for brand-new
   directory objects: the `DELETE` that auto-cleans the app can transiently
   `404` for a few seconds after the `POST` creates it, because the delete
   hits a replica that hasn't received the new object yet. `AzureIAMTool`
   retries the delete with backoff to ride this out. If cleanup ever fails
   for good, the tool raises an error naming the leftover object id — remove
   the orphaned app registration manually with:

   ```bash
   az ad app delete --id <app_object_id-from-the-error>
   ```

## Sixth technique: disable cloud log (`--technique disable-cloud-log`)

This is T1685.002 (Disable or Modify Cloud Log, Defense Impairment) — the agent
using its own token to **silence its own audit trail**. Diagnostic settings live
in the Azure Resource Manager management plane, so this technique uses an
**ARM-scoped token** (`https://management.azure.com/.default`), not the Graph or
Storage scopes the other techniques use. Gated behind `--confirm-destructive`:
without the flag it lists the resource's diagnostic settings (read-only); with
it, `AzureMonitorTool` captures the target setting, `DELETE`s it (the "Disable
Cloud Log" action), then restores it verbatim so audit logging is re-enabled and
nothing persists — both events land in the Azure Activity Log under the agent SP.

6. **A target resource with a diagnostic setting, and the right RBAC scope.**
   Create a throwaway resource that has a diagnostic setting (a Key Vault routing
   its logs to a Log Analytics workspace works well), then grant the agent SP
   **Monitoring Contributor at *resource-group* scope** — not at the resource
   alone.

   **Why resource-group scope (learned the hard way).** Monitoring Contributor
   on the vault alone lets the SP `GET` and `DELETE` the diagnostic setting but
   **not** write to the setting's *destination* (the Log Analytics workspace), so
   the restore `PUT` comes back **HTTP 403** — after the delete has already
   landed, leaving audit logging OFF until an admin recreates it. Granting
   Monitoring Contributor at RG scope covers both the vault and the workspace.
   Wait for RBAC propagation before running.

   **Abort-before-delete safeguard.** So a missing restore permission can never
   silence logging, `AzureMonitorTool` now pre-flights a no-op restore `PUT`
   *before* the `DELETE`; if that write is forbidden it aborts with the delete
   never issued (audit logging untouched), naming the setting, the HTTP code, and
   this RG-scope fix. If the real restore still fails after a passing pre-flight,
   it raises loudly and names the setting so logging is never left silently off.

   If you'd rather not grant this, skip it and run against LocalStack
   (`--technique disable-cloud-log --cloud localstack`), which cuts a CloudWatch
   Logs group's retention to the 1-day minimum in the sandbox — no real blast
   radius, no new permission.

## Environment

Copy `.env.example` to `.env` and fill in the values from the steps above.
`.env` is git-ignored — never commit real tenant values.

Install the optional dependency group:

```bash
pip install -e ".[dev,entra]"
```

## Running it

```bash
# Real Entra token issuance, escalation stays in the safe LocalStack sandbox
# (the recommended combo for any live/interactive session)
docker compose up -d
bridgelab-attack --mode live --idp entra --cloud localstack

# --- additional-credentials (default technique) ---

# Real Entra -> Azure, but read-only by default (lists the target app's
# existing credentials instead of adding one)
bridgelab-attack --mode live --idp entra --cloud azure

# The one deliberate destructive run, to capture the fallback recording.
# Never run this live/on stage.
bridgelab-attack --mode live --idp entra --cloud azure --confirm-destructive

# --- additional-roles (privilege escalation) ---

# Real Entra -> Azure: always read-only (lists current directory role
# assignments). --confirm-destructive has no effect here, on purpose.
bridgelab-attack --mode live --idp entra --cloud azure --technique additional-roles

# The real destructive self-escalation for this technique only ever runs
# safely inside LocalStack — never against Azure:
bridgelab-attack --mode live --cloud localstack --technique additional-roles --confirm-destructive

# --- out-of-scope-access (lateral movement) ---

# Real Entra -> Azure: reads role assignments for the OUT-OF-SCOPE
# principal, not the agent's own SP. Always read-only — no
# --confirm-destructive behavior exists for this technique.
bridgelab-attack --mode live --idp entra --cloud azure --technique out-of-scope-access

# LocalStack: a real (but harmless) s3:GetObject against the already-seeded
# bridgelab-sensitive-data bucket, using the agent's own over-permissioned
# IAM policy.
bridgelab-attack --mode live --cloud localstack --technique out-of-scope-access

# --- data-collection (bulk collection) ---

# Real Entra -> Azure: fully live, not read-only-capped — lists and reads
# every blob in the scoped container using a Storage-scoped token.
bridgelab-attack --mode live --idp entra --cloud azure --technique data-collection

# LocalStack: real ListBucket + GetObject against every object in the
# already-seeded bridgelab-sensitive-data bucket.
bridgelab-attack --mode live --cloud localstack --technique data-collection

# --- create-account (new backdoor identity) ---

# Real Entra -> Azure, read-only by default (lists existing applications
# instead of creating one).
bridgelab-attack --mode live --idp entra --cloud azure --technique create-account

# The one deliberate destructive run: creates a real App Registration and
# immediately deletes it (auto-cleanup — no leftover to rotate). Never run
# this live/on stage.
bridgelab-attack --mode live --idp entra --cloud azure --technique create-account --confirm-destructive

# LocalStack: creates a throwaway IAM user in the sandbox — no real blast radius.
bridgelab-attack --mode live --cloud localstack --technique create-account

# --- disable-cloud-log (impair audit logging) ---

# Real Entra -> Azure, read-only by default (lists the resource's diagnostic
# settings instead of touching them). Needs AZURE_LOG_RESOURCE_ID and
# AZURE_DIAGNOSTIC_SETTING_NAME set.
bridgelab-attack --mode live --idp entra --cloud azure --technique disable-cloud-log

# The one deliberate destructive run: DELETEs the diagnostic setting then
# restores it (auto re-enabled). Pre-flighted so a restore-permission gap aborts
# before the delete. Needs Monitoring Contributor at RG scope. Never run on stage.
bridgelab-attack --mode live --idp entra --cloud azure --technique disable-cloud-log --confirm-destructive

# LocalStack: cuts a CloudWatch Logs group's retention to 1 day in the sandbox.
bridgelab-attack --mode live --cloud localstack --technique disable-cloud-log
```

Each destructive credentials run adds one client secret to the target app.
Rotate/delete it in the portal afterward if you're capturing multiple takes.
The `create-account` destructive run is self-cleaning — it deletes the App
Registration it creates — so it leaves nothing to rotate afterward.
