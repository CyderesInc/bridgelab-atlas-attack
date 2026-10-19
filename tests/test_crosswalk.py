import json
import csv
import tempfile
from pathlib import Path

from bridgelab.crosswalk import CrosswalkEntry, CROSSWALK_ENTRIES, export_json, export_csv


class TestCrosswalkData:
    def test_entry_count(self):
        assert len(CROSSWALK_ENTRIES) == 10

    def test_all_fields_populated(self):
        for entry in CROSSWALK_ENTRIES:
            assert entry.atlas_technique_id, f"Empty atlas_technique_id in {entry}"
            assert entry.atlas_technique_name, f"Empty atlas_technique_name in {entry}"
            assert entry.bridge_condition, f"Empty bridge_condition in {entry}"
            assert entry.attack_v19_technique_id, f"Empty attack_v19_technique_id in {entry}"
            assert entry.attack_v19_technique_name, f"Empty attack_v19_technique_name in {entry}"
            assert entry.attack_v19_tactic, f"Empty attack_v19_tactic in {entry}"
            assert entry.detection_opportunity, f"Empty detection_opportunity in {entry}"
            assert entry.log_source, f"Empty log_source in {entry}"

    def test_atlas_ids_format(self):
        for entry in CROSSWALK_ENTRIES:
            assert entry.atlas_technique_id.startswith("AML.T"), (
                f"ATLAS ID should start with AML.T: {entry.atlas_technique_id}"
            )

    def test_attack_ids_format(self):
        for entry in CROSSWALK_ENTRIES:
            assert entry.attack_v19_technique_id.startswith("T"), (
                f"ATT&CK ID should start with T: {entry.attack_v19_technique_id}"
            )

    def test_no_duplicate_rows(self):
        keys = [
            (e.atlas_technique_id, e.attack_v19_technique_id, e.bridge_condition)
            for e in CROSSWALK_ENTRIES
        ]
        assert len(keys) == len(set(keys)), "Duplicate crosswalk rows found"

    def test_t1098_001_row_validated_against_entra_azure(self):
        row = next(e for e in CROSSWALK_ENTRIES if e.attack_v19_technique_id == "T1098.001")
        assert "Entra" in row.validated_environments
        assert "AWS/LocalStack" in row.validated_environments

    def test_t1098_003_row_validated_read_only_against_entra_azure(self):
        row = next(e for e in CROSSWALK_ENTRIES if e.attack_v19_technique_id == "T1098.003")
        assert "read-only" in row.validated_environments
        assert "AWS/LocalStack" in row.validated_environments

    def test_t1550_001_row_validated_read_only_against_entra_azure(self):
        row = next(e for e in CROSSWALK_ENTRIES if e.attack_v19_technique_id == "T1550.001")
        assert "read-only" in row.validated_environments
        assert "AWS/LocalStack" in row.validated_environments

    def test_t1530_row_validated_against_localstack_and_entra_azure(self):
        row = next(e for e in CROSSWALK_ENTRIES if e.attack_v19_technique_id == "T1530")
        assert "AWS/LocalStack (live)" in row.validated_environments
        assert "Entra ID/Azure (live)" in row.validated_environments

    def test_t1136_003_row_validated_live_on_entra_azure(self):
        # Entra/Azure branch live-verified 2026-09-24 (real App Registration
        # created and auto-removed). The LocalStack branch is code-complete but
        # not yet run against real LocalStack, so it is NOT marked live.
        row = next(e for e in CROSSWALK_ENTRIES if e.attack_v19_technique_id == "T1136.003")
        assert "Entra ID/Azure (live)" in row.validated_environments
        assert "AWS/LocalStack (code-complete" in row.validated_environments

    def test_t1685_002_row_validated_live_on_both_stacks(self):
        # LocalStack branch live-verified 2026-09-29 (real Keycloak token +
        # real CloudWatch Logs PutRetentionPolicy, retention reduced to 1 day).
        # Azure branch live-verified 2026-09-29 (real agent SP token +
        # ARM diagnostic-setting delete-then-restore against a live Key Vault,
        # audit logging re-enabled; abort-before-delete pre-flight in place).
        row = next(e for e in CROSSWALK_ENTRIES if e.attack_v19_technique_id == "T1685.002")
        assert "AWS/LocalStack (live)" in row.validated_environments
        assert "Entra ID/Azure (live)" in row.validated_environments

    def test_validated_environments_defaults_for_undemonstrated_rows(self):
        demonstrated = {"T1098.001", "T1098.003", "T1550.001", "T1530", "T1136.003", "T1685.002"}
        other_rows = [e for e in CROSSWALK_ENTRIES if e.attack_v19_technique_id not in demonstrated]
        assert all(e.validated_environments == "AWS/LocalStack" for e in other_rows)


class TestCrosswalkExport:
    def test_export_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "crosswalk.json"
            export_json(CROSSWALK_ENTRIES, path)
            data = json.loads(path.read_text())
            assert isinstance(data, list)
            assert len(data) == 10
            assert "atlas_technique_id" in data[0]
            assert "attack_v19_technique_id" in data[0]

    def test_export_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "crosswalk.csv"
            export_csv(CROSSWALK_ENTRIES, path)
            with open(path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            assert len(rows) == 10
            assert "atlas_technique_id" in rows[0]
            assert "bridge_condition" in rows[0]
