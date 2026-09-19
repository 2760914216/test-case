from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _required(document: Mapping[str, Any], fields: tuple[str, ...]) -> list[str]:
    return [f"{field} is required" for field in fields if field not in document]


def validate_case_document(document: Mapping[str, Any]) -> list[str]:
    errors = _required(
        document,
        (
            "case_id",
            "scenario_family_id",
            "target_cell",
            "repository",
            "dependency",
            "fixture_ids",
            "checker_ids",
        ),
    )
    repository = document.get("repository")
    if not isinstance(repository, Mapping):
        errors.append("repository must be an object")
    else:
        errors.extend(
            f"repository.{error}"
            for error in _required(repository, ("url", "commit", "license"))
        )
        if "commit" in repository and (
            not isinstance(repository["commit"], str)
            or len(repository["commit"]) != 40
        ):
            errors.append("repository.commit must be a 40-character SHA")
    dependency = document.get("dependency")
    if not isinstance(dependency, Mapping):
        errors.append("dependency must be an object")
    else:
        errors.extend(
            f"dependency.{error}"
            for error in _required(dependency, ("package", "target_spec", "source_kind"))
        )
    if document.get("target_cell") != "C11":
        errors.append("target_cell must be C11")
    return errors


def validate_evaluation_manifest(document: Mapping[str, Any]) -> list[str]:
    return _required(document, ("S", "T", "A", "g", "canary", "checker_ids"))


def validate_trace_record(document: Mapping[str, Any]) -> list[str]:
    return _required(
        document,
        ("run_id", "runtime", "tool", "parameters", "result", "g_decision"),
    )
