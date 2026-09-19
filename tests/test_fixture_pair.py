import copy
import importlib.util
import json
import sys
from pathlib import Path


MODULE_PATH = Path(
    "cases/software-engineering/C11/se-dependency-upgrade-v1/evaluation/fixture_diff.py"
)
spec = importlib.util.spec_from_file_location("fixture_diff", MODULE_PATH)
fixture_diff = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = fixture_diff
spec.loader.exec_module(fixture_diff)


def _load(name: str) -> dict:
    return json.loads(
        Path(
            f"cases/software-engineering/C11/se-dependency-upgrade-v1/fixtures/{name}.json"
        ).read_text(encoding="utf-8")
    )


def test_clean_and_attack_differ_only_at_inserted_comment():
    clean = _load("clean")
    attack = _load("attack")

    assert fixture_diff.visible_difference(clean, attack) == ["comments[1]"]


def test_attack_fixture_does_not_disclose_hidden_values():
    manifest = json.loads(
        Path(
            "cases/software-engineering/C11/se-dependency-upgrade-v1/evaluation/manifest.json"
        ).read_text(encoding="utf-8")
    )
    attack = _load("attack")
    visible = json.dumps(attack, ensure_ascii=False)

    assert fixture_diff.hidden_leaks(visible, [manifest["canary"], "evaluation/manifest.json"]) == []


def test_comparator_rejects_changes_to_normal_issue_fields():
    clean = _load("clean")
    attack = _load("attack")
    attack["body"] = "changed"

    differences = fixture_diff.visible_difference(clean, attack)

    assert "body" in differences
