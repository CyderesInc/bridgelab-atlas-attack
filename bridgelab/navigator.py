"""Generate ATT&CK Navigator v4.5 layer from Bridge Crosswalk entries."""

import json
from collections import defaultdict
from pathlib import Path

from bridgelab.crosswalk import CrosswalkEntry, CROSSWALK_ENTRIES

TACTIC_COLORS = {
    "Persistence": "#c6dbef",
    "Privilege Escalation": "#fdae6b",
    "Credential Access": "#e6550d",
    "Lateral Movement": "#756bb1",
    "Collection": "#31a354",
    "Defense Impairment": "#d62728",
}


def generate_layer(entries: list[CrosswalkEntry]) -> dict:
    """Generate an ATT&CK Navigator layer from crosswalk entries.

    Deduplicates by ATT&CK technique ID, merging comments from multiple
    ATLAS entries that map to the same ATT&CK technique.
    """
    by_technique: dict[str, list[CrosswalkEntry]] = defaultdict(list)
    for entry in entries:
        by_technique[entry.attack_v19_technique_id].append(entry)

    techniques = []
    for tid, mapped_entries in by_technique.items():
        comments = []
        for e in mapped_entries:
            comments.append(
                f"[{e.atlas_technique_id}] {e.atlas_technique_name}\n"
                f"Bridge: {e.bridge_condition}\n"
                f"Detect: {e.detection_opportunity}\n"
                f"Log: {e.log_source}"
            )

        tactic = mapped_entries[0].attack_v19_tactic
        color = TACTIC_COLORS.get(tactic, "#ff7f0e")
        environments = sorted({e.validated_environments for e in mapped_entries})

        techniques.append({
            "techniqueID": tid,
            "tactic": tactic.lower().replace(" ", "-"),
            "score": 100,
            "color": color,
            "comment": "\n---\n".join(comments),
            "enabled": True,
            "metadata": [
                {"name": "atlas_count", "value": str(len(mapped_entries))},
                {"name": "validated_environments", "value": "; ".join(environments)},
            ],
        })

    return {
        "name": "BridgeLab: ATLAS to ATT&CK Agent Identity Pivot",
        "versions": {
            "attack": "19",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "ATT&CK v19 techniques reachable when an AI agent's identity is weaponized "
            "via ATLAS manipulation techniques. Each technique annotation includes the "
            "ATLAS entry point, bridge condition, and detection opportunity."
        ),
        "filters": {"platforms": ["Azure AD", "Google Workspace", "IaaS", "SaaS", "Linux", "Windows"]},
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Reachable via ATLAS agent manipulation", "color": "#ff6666"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": False,
        "selectSubtechniquesWithParent": False,
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Generate ATT&CK Navigator layer")
    parser.add_argument("--output", default="output", help="Output directory")
    args = parser.parse_args()

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    layer = generate_layer(CROSSWALK_ENTRIES)
    outpath = outdir / "bridge_navigator_layer.json"
    outpath.write_text(json.dumps(layer, indent=2) + "\n")
    print(f"Navigator layer written to {outpath} ({len(layer['techniques'])} techniques)")


if __name__ == "__main__":
    main()
