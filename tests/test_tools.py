import pytest
from unittest.mock import MagicMock, patch

from bridgelab.tools import (
    AzureIAMTool,
    AzureMonitorTool,
    CloudLogTool,
    MockAzureIAMTool,
    MockAzureMonitorTool,
    MockCloudIAMTool,
    MockCloudLogTool,
)


class TestMockDisableCloudLog:
    def test_mock_disable_log_modifies_retention(self):
        result = MockCloudLogTool().execute("disable_log", log_group_name="bridgelab-audit")
        assert result["log_group_name"] == "bridgelab-audit"
        assert result["retention_days"] == 1
        assert result["status"] == "Modified"

    def test_mock_unknown_action_raises(self):
        with pytest.raises(ValueError):
            MockCloudLogTool().execute("bogus")

    def test_mock_azure_disable_log_is_disabled_then_restored(self):
        result = MockAzureMonitorTool().execute(
            "disable_log", resource_id="/subscriptions/x/rg", setting_name="bridgelab-audit-diagnostics"
        )
        assert result["setting_name"] == "bridgelab-audit-diagnostics"
        assert result["restored"] is True
        assert result["dry_run"] is False


class TestAzureDisableLog:
    def test_dry_run_lists_only_and_deletes_nothing(self):
        tool = AzureMonitorTool(token="t", confirm_destructive=False)
        list_resp = MagicMock()
        list_resp.raise_for_status = lambda: None
        list_resp.json.return_value = {"value": [{"name": "s1"}, {"name": "s2"}]}
        with patch("bridgelab.tools.httpx.get", return_value=list_resp) as mget, patch(
            "bridgelab.tools.httpx.delete"
        ) as mdel, patch("bridgelab.tools.httpx.put") as mput:
            result = tool.execute(
                "disable_log", resource_id="/subscriptions/x/rg", setting_name="s1"
            )

        mget.assert_called_once()
        mdel.assert_not_called()
        mput.assert_not_called()
        assert result["dry_run"] is True
        assert result["existing_setting_count"] == 2
        assert result["setting_name"] is None

    def test_confirmed_disables_then_restores(self):
        tool = AzureMonitorTool(token="t", confirm_destructive=True)
        get_resp = MagicMock()
        get_resp.raise_for_status = lambda: None
        get_resp.json.return_value = {"properties": {"logs": [{"category": "Audit", "enabled": True}]}}
        del_resp = MagicMock(status_code=204)
        del_resp.raise_for_status = lambda: None
        put_resp = MagicMock(status_code=200)
        with patch("bridgelab.tools.httpx.get", return_value=get_resp) as mget, patch(
            "bridgelab.tools.httpx.delete", return_value=del_resp
        ) as mdel, patch("bridgelab.tools.httpx.put", return_value=put_resp) as mput:
            result = tool.execute(
                "disable_log", resource_id="/subscriptions/x/rg", setting_name="bridgelab-audit-diagnostics"
            )

        mget.assert_called_once()
        mdel.assert_called_once()
        # the delete targets the named diagnostic setting
        assert "bridgelab-audit-diagnostics" in mdel.call_args[0][0]
        # two PUTs: the pre-flight restore-write check, then the real restore —
        # both put the captured properties back
        assert mput.call_count == 2
        for call in mput.call_args_list:
            assert call.kwargs["json"] == {
                "properties": {"logs": [{"category": "Audit", "enabled": True}]}
            }
        assert result["restored"] is True
        assert result["dry_run"] is False

    def test_confirmed_aborts_before_delete_when_capture_unrestorable(self):
        """Abort-before-delete hardening: if the captured setting has no
        restorable 'properties', the tool must raise WITHOUT issuing the DELETE,
        so live audit logging is never disabled when it could not be re-enabled."""
        tool = AzureMonitorTool(token="t", confirm_destructive=True)
        get_resp = MagicMock()
        get_resp.raise_for_status = lambda: None
        get_resp.json.return_value = {}  # no 'properties' -> nothing to restore from
        with patch("bridgelab.tools.httpx.get", return_value=get_resp), patch(
            "bridgelab.tools.httpx.delete"
        ) as mdel, patch("bridgelab.tools.httpx.put") as mput:
            with pytest.raises(RuntimeError) as exc:
                tool.execute(
                    "disable_log", resource_id="/subscriptions/x/rg", setting_name="bridgelab-audit-diagnostics"
                )

        mdel.assert_not_called()
        mput.assert_not_called()
        assert "bridgelab-audit-diagnostics" in str(exc.value)
        assert "BEFORE" in str(exc.value).upper()

    def test_confirmed_aborts_before_delete_if_restore_write_forbidden(self):
        """The real 2026-09-29 failure mode: GET+DELETE are allowed but the
        restore PUT is forbidden (HTTP 403). The pre-flight restore-write must
        catch this and raise WITHOUT deleting, so audit logging is never left off."""
        tool = AzureMonitorTool(token="t", confirm_destructive=True)
        get_resp = MagicMock()
        get_resp.raise_for_status = lambda: None
        get_resp.json.return_value = {"properties": {"logs": [{"category": "Audit", "enabled": True}]}}
        forbidden_put = MagicMock(status_code=403)
        with patch("bridgelab.tools.httpx.get", return_value=get_resp), patch(
            "bridgelab.tools.httpx.delete"
        ) as mdel, patch("bridgelab.tools.httpx.put", return_value=forbidden_put) as mput:
            with pytest.raises(RuntimeError) as exc:
                tool.execute(
                    "disable_log", resource_id="/subscriptions/x/rg", setting_name="bridgelab-audit-diagnostics"
                )

        mput.assert_called_once()  # only the pre-flight PUT ran; no restore needed
        mdel.assert_not_called()   # never deleted — logging untouched
        assert "bridgelab-audit-diagnostics" in str(exc.value)
        assert "403" in str(exc.value)
        assert "BEFORE" in str(exc.value).upper()

    def test_confirmed_raises_when_restore_fails(self):
        """Defense-in-depth: even after a passing pre-flight, if the real restore
        PUT fails post-delete the tool must fail loudly and name the setting —
        audit logging must never be left silently disabled."""
        tool = AzureMonitorTool(token="t", confirm_destructive=True)
        get_resp = MagicMock()
        get_resp.raise_for_status = lambda: None
        get_resp.json.return_value = {"properties": {"logs": []}}
        del_resp = MagicMock(status_code=204)
        del_resp.raise_for_status = lambda: None
        ok_put = MagicMock(status_code=200)      # pre-flight succeeds
        failed_put = MagicMock(status_code=500)  # real restore fails
        with patch("bridgelab.tools.httpx.get", return_value=get_resp), patch(
            "bridgelab.tools.httpx.delete", return_value=del_resp
        ) as mdel, patch("bridgelab.tools.httpx.put", side_effect=[ok_put, failed_put]) as mput:
            with pytest.raises(RuntimeError) as exc:
                tool.execute(
                    "disable_log", resource_id="/subscriptions/x/rg", setting_name="bridgelab-audit-diagnostics"
                )

        mdel.assert_called_once()       # delete did happen this time
        assert mput.call_count == 2     # pre-flight (ok) then restore (failed)
        assert "bridgelab-audit-diagnostics" in str(exc.value)
        assert "LEFT" in str(exc.value).upper()


class TestCloudLogTool:
    def test_disable_log_creates_group_then_shrinks_retention(self):
        """The live tool ensures the target audit group exists, then reduces its
        retention to the 1-day minimum (the T1685.002 'Modify Cloud Log' action)."""
        fake_logs = MagicMock()
        with patch("bridgelab.tools.boto3.client", return_value=fake_logs):
            tool = CloudLogTool(endpoint_url="http://localhost:4566")
            result = tool.execute("disable_log", log_group_name="bridgelab-audit")

        fake_logs.create_log_group.assert_called_once_with(logGroupName="bridgelab-audit")
        fake_logs.put_retention_policy.assert_called_once_with(
            logGroupName="bridgelab-audit", retentionInDays=1
        )
        assert result["retention_days"] == 1
        assert result["status"] == "Modified"


class TestMockCreateAccount:
    def test_mock_cloud_iam_create_user(self):
        result = MockCloudIAMTool().execute("create_user", username="bridgelab-backup-agent")
        assert result["username"] == "bridgelab-backup-agent"
        assert result["status"] == "Created"

    def test_mock_azure_create_account_is_created_and_cleaned_up(self):
        result = MockAzureIAMTool().execute("create_account", display_name="bridgelab-backup-agent")
        assert result["app_object_id"]
        assert result["cleaned_up"] is True
        assert result["dry_run"] is False


class TestAzureCreateAccount:
    def test_dry_run_lists_only_and_creates_nothing(self):
        tool = AzureIAMTool(token="t", confirm_destructive=False)
        list_resp = MagicMock()
        list_resp.raise_for_status = lambda: None
        list_resp.json.return_value = {"value": [{"id": "a"}, {"id": "b"}]}
        with patch("bridgelab.tools.httpx.get", return_value=list_resp) as mget, patch(
            "bridgelab.tools.httpx.post"
        ) as mpost, patch("bridgelab.tools.httpx.delete") as mdel:
            result = tool.execute("create_account", display_name="bridgelab-backup-agent")

        mget.assert_called_once()
        mpost.assert_not_called()
        mdel.assert_not_called()
        assert result["dry_run"] is True
        assert result["existing_application_count"] == 2
        assert result["app_object_id"] is None

    def test_confirmed_creates_then_deletes_the_backdoor_app(self):
        tool = AzureIAMTool(token="t", confirm_destructive=True)
        post_resp = MagicMock()
        post_resp.raise_for_status = lambda: None
        post_resp.json.return_value = {
            "appId": "app-123",
            "id": "obj-456",
            "displayName": "bridgelab-backup-agent",
        }
        del_resp = MagicMock(status_code=204)
        with patch("bridgelab.tools.httpx.post", return_value=post_resp) as mpost, patch(
            "bridgelab.tools.httpx.delete", return_value=del_resp
        ) as mdel:
            result = tool.execute("create_account", display_name="bridgelab-backup-agent")

        mpost.assert_called_once()
        mdel.assert_called_once()
        # the deletion targets the object ID of the app we just created
        assert "obj-456" in mdel.call_args[0][0]
        assert result["app_id"] == "app-123"
        assert result["app_object_id"] == "obj-456"
        assert result["cleaned_up"] is True
        assert result["dry_run"] is False

    def test_confirmed_retries_delete_until_new_app_propagates(self):
        """Graph is eventually consistent for new directory objects: a DELETE
        issued right after POST can 404 until the app replicates. The tool must
        retry the delete rather than orphan the backdoor app."""
        tool = AzureIAMTool(token="t", confirm_destructive=True)
        post_resp = MagicMock()
        post_resp.raise_for_status = lambda: None
        post_resp.json.return_value = {"appId": "app-123", "id": "obj-456"}
        propagating = MagicMock(status_code=404)
        deleted = MagicMock(status_code=204)
        with patch("bridgelab.tools.httpx.post", return_value=post_resp), patch(
            "bridgelab.tools.httpx.delete", side_effect=[propagating, propagating, deleted]
        ) as mdel, patch("bridgelab.tools.time.sleep") as msleep:
            result = tool.execute("create_account", display_name="bridgelab-backup-agent")

        assert mdel.call_count == 3
        assert msleep.called
        assert result["cleaned_up"] is True

    def test_confirmed_raises_with_object_id_when_delete_never_succeeds(self):
        """If cleanup never succeeds, the tool must fail loudly and name the
        leftover object id so the orphaned backdoor app can be removed by hand
        — never silently leave it behind."""
        tool = AzureIAMTool(token="t", confirm_destructive=True)
        post_resp = MagicMock()
        post_resp.raise_for_status = lambda: None
        post_resp.json.return_value = {"appId": "app-123", "id": "obj-456"}
        still_propagating = MagicMock(status_code=404)
        with patch("bridgelab.tools.httpx.post", return_value=post_resp), patch(
            "bridgelab.tools.httpx.delete", return_value=still_propagating
        ), patch("bridgelab.tools.time.sleep"):
            with pytest.raises(RuntimeError) as exc:
                tool.execute("create_account", display_name="bridgelab-backup-agent")

        assert "obj-456" in str(exc.value)
