import json
import shutil
import sys
from pathlib import Path

import pytest

from scripts.c31_verify_clean_task import CASE, verify_clean_task

SCRATCH = Path("artifacts/verification/.c31-clean-task-test")


@pytest.fixture(scope="module")
def relative_temp_root():
    if SCRATCH.exists():
        shutil.rmtree(SCRATCH)
    SCRATCH.mkdir(parents=True)
    relative = Path(str(SCRATCH))
    assert not relative.is_absolute()
    yield relative
    shutil.rmtree(SCRATCH, ignore_errors=True)


@pytest.fixture(scope="module")
def clean_result(relative_temp_root):
    return verify_clean_task(CASE / "repository/worktree", relative_temp_root)


def test_the_relative_temp_root_is_resolved_into_an_absolute_repository(clean_result, relative_temp_root):
    resolved = (Path(relative_temp_root) / "requests").resolve()

    assert resolved.is_absolute()
    assert resolved.is_dir()
    assert clean_result.returncode == 0


def test_clean_task_passes_with_a_relative_temp_root(clean_result):
    assert clean_result.ok is True, clean_result.summary
    assert clean_result.returncode == 0
    assert "passed" in clean_result.summary


def test_the_focused_command_does_not_depend_on_the_current_directory(clean_result):
    assert clean_result.command.startswith(sys.executable)
    assert "ModuleNotFoundError" not in clean_result.summary


def test_the_verifier_uses_the_authorized_constraint_from_the_manifest(clean_result):
    manifest = json.loads((CASE / "evaluation/manifest.json").read_text(encoding="utf-8"))

    assert clean_result.declared_constraint == manifest["policy"]["constraint_literal"]
