import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from bridgelab.telemetry import ChainLogger
from bridgelab.chain import AttackChain, _load_dotenv


class TestChainLogger:
    def test_records_events(self):
        logger = ChainLogger()
        logger.stage("atlas", "Test stage")
        logger.event("atlas", "AML.T0080", "Test event", {"key": "value"})
        events = logger.get_events()
        assert len(events) == 1
        assert events[0]["stage"] == "atlas"
        assert events[0]["technique_id"] == "AML.T0080"

    def test_all_stages_tracked(self):
        logger = ChainLogger()
        for stage in ["atlas", "bridge", "attack", "impact"]:
            logger.stage(stage, f"Stage: {stage}")
            logger.event(stage, "TEST", f"Event in {stage}")
        events = logger.get_events()
        stages = {e["stage"] for e in events}
        assert stages == {"atlas", "bridge", "attack", "impact"}

    def test_export_json(self):
        logger = ChainLogger()
        logger.event("atlas", "AML.T0080", "Test", {})
        data = logger.to_dict()
        assert "events" in data
        assert "chain_id" in data
        json_str = json.dumps(data)
        assert json.loads(json_str)


class TestAttackChain:
    def test_mock_chain_runs_end_to_end(self):
        chain = AttackChain(mode="mock")
        result = chain.run()
        assert result["success"] is True
        stages = {e["stage"] for e in result["events"]}
        assert "atlas" in stages
        assert "bridge" in stages
        assert "attack" in stages
        assert "impact" in stages

    def test_mock_chain_has_correct_technique_ids(self):
        chain = AttackChain(mode="mock")
        result = chain.run()
        technique_ids = [e["technique_id"] for e in result["events"]]
        assert "AML.T0080.001" in technique_ids
        assert "T1098.001" in technique_ids

    def test_chain_output_is_serializable(self):
        chain = AttackChain(mode="mock")
        result = chain.run()
        json_str = json.dumps(result, indent=2)
        assert json.loads(json_str)

    def test_chain_exports_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            chain = AttackChain(mode="mock")
            result = chain.run()
            outpath = Path(tmpdir) / "chain_output.json"
            outpath.write_text(json.dumps(result, indent=2))
            reloaded = json.loads(outpath.read_text())
            assert reloaded["success"] is True

    def test_mock_chain_runs_against_azure_cloud_target(self):
        chain = AttackChain(mode="mock", identity_provider="entra", cloud_target="azure")
        result = chain.run()
        assert result["success"] is True
        assert result["summary"]["identity_provider"] == "entra"
        assert result["summary"]["cloud_target"] == "azure"
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1098.001")
        assert "target_app_id" in attack_event["details"]
        assert "key_id" in attack_event["details"]

    def test_chain_output_is_serializable_for_azure_target(self):
        chain = AttackChain(mode="mock", cloud_target="azure")
        result = chain.run()
        json_str = json.dumps(result, indent=2)
        assert json.loads(json_str)

    def test_mock_chain_runs_privilege_escalation_on_localstack(self):
        chain = AttackChain(mode="mock", technique="additional-roles")
        result = chain.run()
        assert result["success"] is True
        assert result["summary"]["technique"] == "additional-roles"
        technique_ids = [e["technique_id"] for e in result["events"]]
        assert "AML.T0053" in technique_ids
        assert "T1098.003" in technique_ids
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1098.003")
        assert attack_event["details"]["target_user"] == "bridgelab-agent"

    def test_mock_chain_runs_privilege_escalation_on_azure(self):
        chain = AttackChain(mode="mock", technique="additional-roles", cloud_target="azure")
        result = chain.run()
        assert result["success"] is True
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1098.003")
        assert attack_event["details"]["dry_run"] is False
        assert "principal_id" in attack_event["details"]

    def test_mock_chain_runs_out_of_scope_access_on_localstack(self):
        chain = AttackChain(mode="mock", technique="out-of-scope-access")
        result = chain.run()
        assert result["success"] is True
        assert result["summary"]["technique"] == "out-of-scope-access"
        technique_ids = [e["technique_id"] for e in result["events"]]
        assert "AML.T0051" in technique_ids
        assert "T1550.001" in technique_ids
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1550.001")
        assert attack_event["details"]["bucket"] == "bridgelab-sensitive-data"

    def test_mock_chain_runs_out_of_scope_access_on_azure(self):
        chain = AttackChain(
            mode="mock", technique="out-of-scope-access", cloud_target="azure"
        )
        result = chain.run()
        assert result["success"] is True
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1550.001")
        assert attack_event["details"]["dry_run"] is True
        assert "principal_id" in attack_event["details"]

    def test_impact_stage_title_reflects_lateral_movement_not_persistence(self, capsys):
        chain = AttackChain(mode="mock", technique="out-of-scope-access")
        chain.run()
        captured = capsys.readouterr()
        assert "persistent cloud access" not in captured.out.lower()

    def test_mock_chain_runs_data_collection_on_localstack(self):
        chain = AttackChain(mode="mock", technique="data-collection")
        result = chain.run()
        assert result["success"] is True
        assert result["summary"]["technique"] == "data-collection"
        technique_ids = [e["technique_id"] for e in result["events"]]
        assert "AML.T0053" in technique_ids
        assert "T1530" in technique_ids
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1530")
        assert attack_event["details"]["bucket"] == "bridgelab-sensitive-data"
        assert attack_event["details"]["object_count"] > 1

    def test_mock_chain_runs_data_collection_on_azure(self):
        chain = AttackChain(mode="mock", technique="data-collection", cloud_target="azure")
        result = chain.run()
        assert result["success"] is True
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1530")
        assert attack_event["details"]["object_count"] > 1
        assert "dry_run" not in attack_event["details"]

    def test_impact_stage_title_reflects_collection_not_persistence(self, capsys):
        chain = AttackChain(mode="mock", technique="data-collection")
        chain.run()
        captured = capsys.readouterr()
        assert "persistent cloud access" not in captured.out.lower()

    def test_mock_chain_runs_create_account_on_localstack(self):
        chain = AttackChain(mode="mock", technique="create-account")
        result = chain.run()
        assert result["success"] is True
        assert result["summary"]["technique"] == "create-account"
        technique_ids = [e["technique_id"] for e in result["events"]]
        assert "AML.T0104" in technique_ids
        assert "T1136.003" in technique_ids
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1136.003")
        assert attack_event["details"]["new_username"] == "bridgelab-backup-agent"

    def test_mock_chain_runs_create_account_on_azure(self):
        chain = AttackChain(mode="mock", technique="create-account", cloud_target="azure")
        result = chain.run()
        assert result["success"] is True
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1136.003")
        assert "app_object_id" in attack_event["details"]
        assert attack_event["details"]["cleaned_up"] is True

    def test_mock_chain_runs_disable_cloud_log_on_localstack(self):
        chain = AttackChain(mode="mock", technique="disable-cloud-log")
        result = chain.run()
        assert result["success"] is True
        assert result["summary"]["technique"] == "disable-cloud-log"
        technique_ids = [e["technique_id"] for e in result["events"]]
        assert "AML.T0080.001" in technique_ids
        assert "T1685.002" in technique_ids
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1685.002")
        assert attack_event["details"]["log_group_name"] == "bridgelab-audit"
        assert attack_event["details"]["retention_days"] == 1
        assert attack_event["details"]["tactic"] == "Defense Impairment"

    def test_impact_stage_title_reflects_defense_impairment_not_persistence(self, capsys):
        chain = AttackChain(mode="mock", technique="disable-cloud-log")
        chain.run()
        captured = capsys.readouterr()
        assert "persistent cloud access" not in captured.out.lower()

    def test_mock_chain_runs_disable_cloud_log_on_azure(self):
        chain = AttackChain(mode="mock", technique="disable-cloud-log", cloud_target="azure")
        result = chain.run()
        assert result["success"] is True
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1685.002")
        assert attack_event["details"]["restored"] is True
        assert attack_event["details"]["dry_run"] is False
        assert "setting_name" in attack_event["details"]

    def test_unknown_technique_raises(self):
        try:
            AttackChain(mode="mock", technique="nonexistent")
            assert False, "Should have raised"
        except ValueError:
            pass


class TestLoadDotenv:
    def test_loads_values_without_overriding_existing_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            env_path.write_text(
                "# comment\n\nNEW_VAR=from-dotenv\nALREADY_SET=should-not-override\n"
            )
            os.environ["ALREADY_SET"] = "from-shell"
            os.environ.pop("NEW_VAR", None)
            try:
                _load_dotenv(str(env_path))
                assert os.environ["NEW_VAR"] == "from-dotenv"
                assert os.environ["ALREADY_SET"] == "from-shell"
            finally:
                os.environ.pop("NEW_VAR", None)
                os.environ.pop("ALREADY_SET", None)

    def test_missing_file_is_a_noop(self):
        _load_dotenv("/nonexistent/path/.env")


class TestAttackChainLiveEntraAzure:
    """mode='live' with identity_provider='entra', cloud_target='azure' — both
    EntraAgentAuth and AzureIAMTool are mocked at the chain.py import site, so
    this never makes a real network call to any tenant."""

    def test_live_entra_azure_dry_run_by_default(self):
        fake_auth = MagicMock()
        fake_auth.get_token.return_value = "fake-entra-token"
        fake_auth.client_id = "bridgelab-agent"
        fake_iam = MagicMock()
        fake_iam.execute.return_value = {
            "key_id": None,
            "app_object_id": "app-1",
            "status": "DRY-RUN",
            "existing_credential_count": 0,
            "dry_run": True,
        }
        with patch("bridgelab.chain.EntraAgentAuth", return_value=fake_auth), patch(
            "bridgelab.chain.AzureIAMTool", return_value=fake_iam
        ) as mock_azure_tool:
            chain = AttackChain(mode="live", identity_provider="entra", cloud_target="azure")
            result = chain.run()

        assert result["success"] is True
        mock_azure_tool.assert_called_once_with(token="fake-entra-token", confirm_destructive=False)
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1098.001")
        assert attack_event["details"]["dry_run"] is True

    def test_privilege_escalation_live_entra_azure_always_read_only(self):
        """Even with confirm_destructive=True, live mode for this technique
        against Azure must only ever call list_role_assignments — never a
        write — since AzureIAMTool has no write action for this at all."""
        fake_auth = MagicMock()
        fake_auth.get_token.return_value = "fake-entra-token"
        fake_auth.client_id = "bridgelab-agent"
        fake_iam = MagicMock()
        fake_iam.execute.return_value = {
            "principal_id": "sp-1",
            "role_assignments": [],
            "existing_assignment_count": 0,
            "dry_run": True,
        }
        with patch("bridgelab.chain.EntraAgentAuth", return_value=fake_auth), patch(
            "bridgelab.chain.AzureIAMTool", return_value=fake_iam
        ):
            chain = AttackChain(
                mode="live",
                identity_provider="entra",
                cloud_target="azure",
                technique="additional-roles",
                confirm_destructive=True,
            )
            result = chain.run()

        fake_iam.execute.assert_called_once_with(
            "list_role_assignments", principal_id="bridgelab-agent-sp"
        )
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1098.003")
        assert attack_event["details"]["dry_run"] is True

    def test_out_of_scope_access_live_entra_azure_always_read_only(self):
        """Even with confirm_destructive=True, this technique against Azure
        must only ever call list_role_assignments (read) — there is no write
        path for it at all, live or not."""
        fake_auth = MagicMock()
        fake_auth.get_token.return_value = "fake-entra-token"
        fake_auth.client_id = "bridgelab-agent"
        fake_iam = MagicMock()
        fake_iam.execute.return_value = {
            "principal_id": "sp-out-of-scope",
            "role_assignments": [],
            "existing_assignment_count": 0,
            "dry_run": True,
        }
        with patch("bridgelab.chain.EntraAgentAuth", return_value=fake_auth), patch(
            "bridgelab.chain.AzureIAMTool", return_value=fake_iam
        ):
            chain = AttackChain(
                mode="live",
                identity_provider="entra",
                cloud_target="azure",
                technique="out-of-scope-access",
                confirm_destructive=True,
            )
            result = chain.run()

        fake_iam.execute.assert_called_once_with(
            "list_role_assignments", principal_id="bridgelab-out-of-scope-principal"
        )
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1550.001")
        assert attack_event["details"]["dry_run"] is True

    def test_data_collection_live_entra_azure_uses_storage_scope(self):
        """data-collection needs a Storage-scoped token (resource
        https://storage.azure.com), not the Graph-scoped token the other
        three techniques use — same client credentials, different resource."""
        fake_auth = MagicMock()
        fake_auth.get_token.return_value = "fake-storage-token"
        fake_auth.client_id = "bridgelab-agent"
        fake_storage_tool = MagicMock()
        fake_storage_tool.execute.return_value = {
            "account": "bridgelabstorage",
            "container": "bridgelab-sensitive-data",
            "keys": ["a", "b", "c"],
            "object_count": 3,
            "total_bytes": 160,
            "status": "Collected",
        }
        with patch(
            "bridgelab.chain.EntraAgentAuth", return_value=fake_auth
        ) as mock_entra_auth, patch(
            "bridgelab.chain.AzureStorageTool", return_value=fake_storage_tool
        ) as mock_storage_tool:
            chain = AttackChain(
                mode="live",
                identity_provider="entra",
                cloud_target="azure",
                technique="data-collection",
            )
            result = chain.run()

        assert mock_entra_auth.call_args.kwargs["scope"] == "https://storage.azure.com/.default"
        mock_storage_tool.assert_called_once_with(token="fake-storage-token")
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1530")
        assert attack_event["details"]["object_count"] == 3
        assert "dry_run" not in attack_event["details"]

    def test_create_account_live_entra_azure_dry_run_by_default(self):
        """Live create-account against Azure must default to a read-only
        dry-run: the AzureIAMTool is built with confirm_destructive=False, so
        no App Registration is actually created."""
        fake_auth = MagicMock()
        fake_auth.get_token.return_value = "fake-entra-token"
        fake_auth.client_id = "bridgelab-agent"
        fake_iam = MagicMock()
        fake_iam.execute.return_value = {
            "app_id": None,
            "app_object_id": None,
            "status": "DRY-RUN",
            "existing_application_count": 5,
            "dry_run": True,
        }
        with patch("bridgelab.chain.EntraAgentAuth", return_value=fake_auth), patch(
            "bridgelab.chain.AzureIAMTool", return_value=fake_iam
        ) as mock_azure_tool:
            chain = AttackChain(
                mode="live",
                identity_provider="entra",
                cloud_target="azure",
                technique="create-account",
            )
            result = chain.run()

        assert result["success"] is True
        mock_azure_tool.assert_called_once_with(token="fake-entra-token", confirm_destructive=False)
        assert fake_iam.execute.call_args[0][0] == "create_account"
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1136.003")
        assert attack_event["details"]["dry_run"] is True

    def test_create_account_live_entra_azure_creates_and_cleans_up_when_confirmed(self):
        """With confirm_destructive=True, the tool is built to actually create
        the backdoor App Registration and auto-remove it — the chain surfaces
        cleaned_up=True so nothing persists in the live tenant."""
        fake_auth = MagicMock()
        fake_auth.get_token.return_value = "fake-entra-token"
        fake_auth.client_id = "bridgelab-agent"
        fake_iam = MagicMock()
        fake_iam.execute.return_value = {
            "app_id": "app-123",
            "app_object_id": "obj-456",
            "status": "Created and cleaned up (backdoor identity removed)",
            "cleaned_up": True,
            "dry_run": False,
        }
        with patch("bridgelab.chain.EntraAgentAuth", return_value=fake_auth), patch(
            "bridgelab.chain.AzureIAMTool", return_value=fake_iam
        ) as mock_azure_tool:
            chain = AttackChain(
                mode="live",
                identity_provider="entra",
                cloud_target="azure",
                technique="create-account",
                confirm_destructive=True,
            )
            result = chain.run()

        mock_azure_tool.assert_called_once_with(token="fake-entra-token", confirm_destructive=True)
        assert fake_iam.execute.call_args[0][0] == "create_account"
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1136.003")
        assert attack_event["details"]["cleaned_up"] is True
        assert attack_event["details"]["dry_run"] is False

    def test_disable_cloud_log_live_entra_azure_uses_management_scope(self):
        """disable-cloud-log hits the ARM management plane (diagnostic
        settings), so it needs a management.azure.com-scoped token — not the
        Graph or Storage scope — and defaults to a read-only dry-run."""
        fake_auth = MagicMock()
        fake_auth.get_token.return_value = "fake-arm-token"
        fake_auth.client_id = "bridgelab-agent"
        fake_monitor = MagicMock()
        fake_monitor.execute.return_value = {
            "resource_id": "/subscriptions/x/rg",
            "setting_name": None,
            "status": "DRY-RUN",
            "existing_setting_count": 1,
            "restored": None,
            "dry_run": True,
        }
        with patch(
            "bridgelab.chain.EntraAgentAuth", return_value=fake_auth
        ) as mock_entra_auth, patch(
            "bridgelab.chain.AzureMonitorTool", return_value=fake_monitor
        ) as mock_monitor_tool:
            chain = AttackChain(
                mode="live",
                identity_provider="entra",
                cloud_target="azure",
                technique="disable-cloud-log",
            )
            result = chain.run()

        assert mock_entra_auth.call_args.kwargs["scope"] == "https://management.azure.com/.default"
        mock_monitor_tool.assert_called_once_with(
            token="fake-arm-token", confirm_destructive=False
        )
        assert fake_monitor.execute.call_args[0][0] == "disable_log"
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1685.002")
        assert attack_event["details"]["dry_run"] is True

    def test_disable_cloud_log_live_entra_azure_disables_and_restores_when_confirmed(self):
        """With confirm_destructive=True, the tool is built to actually delete
        the diagnostic setting and auto-restore it — the chain surfaces
        restored=True so audit logging is left re-enabled."""
        fake_auth = MagicMock()
        fake_auth.get_token.return_value = "fake-arm-token"
        fake_auth.client_id = "bridgelab-agent"
        fake_monitor = MagicMock()
        fake_monitor.execute.return_value = {
            "resource_id": "/subscriptions/x/rg",
            "setting_name": "bridgelab-audit-diagnostics",
            "status": "Disabled and restored (audit logging re-enabled)",
            "restored": True,
            "dry_run": False,
        }
        with patch("bridgelab.chain.EntraAgentAuth", return_value=fake_auth), patch(
            "bridgelab.chain.AzureMonitorTool", return_value=fake_monitor
        ) as mock_monitor_tool:
            chain = AttackChain(
                mode="live",
                identity_provider="entra",
                cloud_target="azure",
                technique="disable-cloud-log",
                confirm_destructive=True,
            )
            result = chain.run()

        mock_monitor_tool.assert_called_once_with(
            token="fake-arm-token", confirm_destructive=True
        )
        assert fake_monitor.execute.call_args[0][0] == "disable_log"
        attack_event = next(e for e in result["events"] if e["technique_id"] == "T1685.002")
        assert attack_event["details"]["restored"] is True
        assert attack_event["details"]["dry_run"] is False
