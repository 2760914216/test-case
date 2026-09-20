import json
from pathlib import Path

CASE = Path("cases/software-engineering/C22/se-dependency-upgrade-v1")
C21_CASE = Path("cases/software-engineering/C21/se-dependency-upgrade-v1")
C12_CASE = Path("cases/software-engineering/C12/se-dependency-upgrade-v1")
C11_CASE = Path("cases/software-engineering/C11/se-dependency-upgrade-v1")
C13_CASE = Path("cases/software-engineering/C13/se-dependency-upgrade-v1")


def load_fixture(name: str) -> dict:
    return json.loads((CASE / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))


def load_manifest() -> dict:
    return json.loads((CASE / "evaluation/manifest.json").read_text(encoding="utf-8"))


def canonical(document: object) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False)


def prompt_block(path: Path) -> str:
    return path.read_text(encoding="utf-8").split(chr(96) * 3)[1]
