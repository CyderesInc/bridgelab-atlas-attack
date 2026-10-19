import json
import tempfile
from pathlib import Path

from bridgelab.crosswalk import CROSSWALK_ENTRIES
from bridgelab.navigator import generate_layer, TACTIC_COLORS


class TestNavigatorLayer:
    def test_layer_has_required_fields(self):
        layer = generate_layer(CROSSWALK_ENTRIES)
        assert layer["name"]
        assert layer["domain"] == "enterprise-attack"
        assert "versions" in layer
        assert layer["versions"]["attack"] == "19"
        assert layer["versions"]["layer"] == "4.5"

    def test_layer_has_description(self):
        layer = generate_layer(CROSSWALK_ENTRIES)
        assert "ATLAS" in layer["description"]
        assert "ATT&CK" in layer["description"]

    def test_techniques_present(self):
        layer = generate_layer(CROSSWALK_ENTRIES)
        technique_ids = {t["techniqueID"] for t in layer["techniques"]}
        for entry in CROSSWALK_ENTRIES:
            tid = entry.attack_v19_technique_id
            base_tid = tid.split(".")[0] if "." in tid else tid
            assert tid in technique_ids or base_tid in technique_ids, (
                f"Technique {tid} from crosswalk not found in Navigator layer"
            )

    def test_techniques_have_comments(self):
        layer = generate_layer(CROSSWALK_ENTRIES)
        for tech in layer["techniques"]:
            assert tech.get("comment"), f"No comment on technique {tech['techniqueID']}"

    def test_techniques_have_scores(self):
        layer = generate_layer(CROSSWALK_ENTRIES)
        for tech in layer["techniques"]:
            assert "score" in tech
            assert 0 <= tech["score"] <= 100

    def test_deduplicated_technique_ids(self):
        layer = generate_layer(CROSSWALK_ENTRIES)
        ids = [t["techniqueID"] for t in layer["techniques"]]
        assert len(ids) == len(set(ids)), "Duplicate technique IDs in layer"

    def test_gradient_defined(self):
        layer = generate_layer(CROSSWALK_ENTRIES)
        assert "gradient" in layer
        assert len(layer["gradient"]["colors"]) >= 2


class TestNavigatorExport:
    def test_export_valid_json(self):
        layer = generate_layer(CROSSWALK_ENTRIES)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "layer.json"
            path.write_text(json.dumps(layer, indent=2))
            reloaded = json.loads(path.read_text())
            assert reloaded["name"] == layer["name"]
