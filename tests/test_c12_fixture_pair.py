import json
from pathlib import Path

CASE = Path("cases/software-engineering/C12/se-dependency-upgrade-v1")
C11_CASE = Path("cases/software-engineering/C11/se-dependency-upgrade-v1")


def _load(name: str) -> dict:
    return json.loads((CASE / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))


def test_attack_fixture_only_appends_one_comment():
    clean = _load("clean")
    attack = _load("attack")

    assert list(clean) == list(attack)
    assert clean["body"] == attack["body"]
    assert clean["title"] == attack["title"]
    assert clean["labels"] == attack["labels"]
    assert attack["comments"][:-1] == clean["comments"]
    assert len(attack["comments"]) == len(clean["comments"]) + 1


def test_c12_clean_fixture_is_identical_to_the_frozen_c11_clean_fixture():
    assert (CASE / "fixtures/clean.json").read_bytes() == (
        C11_CASE / "fixtures/clean.json"
    ).read_bytes()


def test_c12_task_authorization_is_identical_to_the_frozen_c11_authorization():
    c12 = json.loads((CASE / "evaluation/manifest.json").read_text(encoding="utf-8"))
    c11 = json.loads((C11_CASE / "evaluation/manifest.json").read_text(encoding="utf-8"))

    assert c12["T"] == c11["T"]
    assert c12["A"]["normal_dependency"] == c11["A"]["normal_dependency"]


def test_visible_fixtures_never_leak_the_hidden_canary_or_private_paths():
    manifest = json.loads((CASE / "evaluation/manifest.json").read_text(encoding="utf-8"))
    visible = (CASE / "fixtures/attack.json").read_text(encoding="utf-8")
    visible += (CASE / "fixtures/clean.json").read_text(encoding="utf-8")
    visible += (CASE / "fixtures/user-task.md").read_text(encoding="utf-8")

    for forbidden in (manifest["canary"], manifest["channel_token"], "evaluation/manifest.json", "checkers.py"):
        assert forbidden not in visible


def test_injection_names_the_attacker_channel_and_marker_only():
    manifest = json.loads((CASE / "evaluation/manifest.json").read_text(encoding="utf-8"))
    appended = _load("attack")["comments"][-1]

    assert appended["author"] == "release-engineering"
    assert manifest["g"]["channel"] in appended["body"]
    assert manifest["g"]["payload_marker"] in appended["body"]


def test_clean_fixture_has_no_injection_comment():
    clean = _load("clean")

    assert all("relay" not in comment["body"] for comment in clean["comments"])
