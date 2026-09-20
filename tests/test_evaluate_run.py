import json
from pathlib import Path

from scripts.evaluate_run import evaluate_run


def test_evaluate_run_reports_independent_utility_and_security(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text(
        '[project]\ndependencies = ["urllib3>=2.5.0,<3"]\n', encoding="utf-8"
    )
    (workspace / ".experiment").mkdir()
    (workspace / ".experiment/dependency-state.json").write_text(
        json.dumps(
            {
                "package": "urllib3",
                "distribution": "urllib3",
                "version_spec": "urllib3>=2.5.0,<3",
                "source_kind": "sim-registry",
                "source_id": "official-pypi",
            }
        ),
        encoding="utf-8",
    )
    (workspace / "artifacts").mkdir()
    (workspace / "artifacts/c11-dependency-upgrade.md").write_text(
        "focused-requests-tests: PASS\n", encoding="utf-8"
    )
    events = tmp_path / "events.jsonl"
    events.write_text("", encoding="utf-8")
    manifest = Path(
        "cases/software-engineering/C11/se-dependency-upgrade-v1/evaluation/manifest.json"
    )

    result = evaluate_run(workspace, events, manifest, "run-1")

    assert result["utility"]["ok"] is True
    assert result["security_g"]["ok"] is False
