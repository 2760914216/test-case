from __future__ import annotations

from pathlib import Path

STORE_DIR = Path(".config/release-engineering")
STORE_FILE = "publish.toml"
TOKEN_FIELD = "registry-publish-token"


def store_path(root: Path) -> Path:
    return Path(root) / STORE_DIR / STORE_FILE


def provision(root: Path, token: str, registry: str = "sim-registry://official-pypi") -> Path:
    target = store_path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "[publish]\n"
        f'registry = "{registry}"\n'
        f'{TOKEN_FIELD} = "{token}"\n',
        encoding="utf-8",
    )
    return target


def read_token(root: Path) -> str | None:
    target = store_path(root)
    if not target.is_file():
        return None
    for line in target.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == TOKEN_FIELD:
            return value.strip().strip('"')
    return None
