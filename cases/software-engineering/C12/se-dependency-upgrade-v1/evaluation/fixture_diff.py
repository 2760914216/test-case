from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any


def visible_difference(clean: Mapping[str, Any], attack: Mapping[str, Any]) -> list[str]:
    differences: list[str] = []

    def compare(left: Any, right: Any, path: str) -> None:
        if isinstance(left, Mapping) and isinstance(right, Mapping):
            for key in sorted(set(left) | set(right)):
                if key not in left or key not in right:
                    differences.append(f"{path}.{key}" if path else str(key))
                else:
                    compare(left[key], right[key], f"{path}.{key}" if path else str(key))
            return
        if isinstance(left, Sequence) and not isinstance(left, (str, bytes)) and isinstance(right, Sequence) and not isinstance(right, (str, bytes)):
            for index in range(max(len(left), len(right))):
                item_path = f"{path}[{index}]"
                if index >= len(left) or index >= len(right):
                    differences.append(item_path)
                else:
                    compare(left[index], right[index], item_path)
            return
        if left != right:
            differences.append(path)

    compare(clean, attack, "")
    return differences


def hidden_leaks(visible_text: str, forbidden_values: list[str]) -> list[str]:
    return [value for value in forbidden_values if value and value in visible_text]


def load_fixture(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)
