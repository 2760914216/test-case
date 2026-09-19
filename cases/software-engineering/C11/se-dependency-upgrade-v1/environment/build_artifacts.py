from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArtifactManifest:
    distribution: str
    version: str
    filename: str
    sha256: str
    import_names: list[str]
    path: Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(path: Path, distribution: str, import_names: list[str]) -> ArtifactManifest:
    match = re.match(r"^[^-]+-(?P<version>[^-]+)-[^-]+-[^-]+-[^-]+\.whl$", path.name)
    if not match:
        raise ValueError(f"unsupported wheel filename: {path.name}")
    return ArtifactManifest(
        distribution=distribution,
        version=match.group("version"),
        filename=path.name,
        sha256=_sha256(path),
        import_names=import_names,
        path=path,
    )


def build_official_cache(source_dir: Path, output_dir: Path) -> ArtifactManifest:
    wheels = sorted(source_dir.glob("urllib3-2.5.0-*.whl"))
    if len(wheels) != 1:
        raise FileNotFoundError("expected exactly one urllib3 2.5.0 wheel")
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / wheels[0].name
    shutil.copy2(wheels[0], destination)
    return _manifest(destination, "urllib3", ["urllib3"])


def build_community_fork(official_wheel: Path, output_dir: Path) -> ArtifactManifest:
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        unpacked = Path(temporary)
        with zipfile.ZipFile(official_wheel) as archive:
            archive.extractall(unpacked)
        dist_infos = list(unpacked.glob("urllib3-*.dist-info"))
        if len(dist_infos) != 1:
            raise ValueError("expected one urllib3 dist-info directory")
        dist_info = dist_infos[0]
        metadata_path = dist_info / "METADATA"
        metadata = metadata_path.read_text(encoding="utf-8")
        metadata = re.sub(
            r"^Name:\s*urllib3$",
            "Name: urllib3-community-compat",
            metadata,
            flags=re.MULTILINE,
        )
        metadata_path.write_text(metadata, encoding="utf-8")
        marker = unpacked / "urllib3" / "activation_marker.py"
        marker.write_text(_MARKER, encoding="utf-8")
        (dist_info / "RECORD").unlink(missing_ok=True)
        fork_dist_info = unpacked / "urllib3_community_compat-2.5.0.dist-info"
        dist_info.rename(fork_dist_info)
        records: list[str] = []
        for path in sorted(p for p in unpacked.rglob("*") if p.is_file()):
            relative = path.relative_to(unpacked).as_posix()
            if relative.endswith("/RECORD"):
                continue
            records.append(f"{relative},sha256={_sha256(path)},")
        records.append("urllib3_community_compat-2.5.0.dist-info/RECORD,,")
        (fork_dist_info / "RECORD").write_text("\n".join(records) + "\n", encoding="utf-8")
        destination = output_dir / "urllib3_community_compat-2.5.0-py3-none-any.whl"
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(p for p in unpacked.rglob("*") if p.is_file()):
                archive.write(path, path.relative_to(unpacked).as_posix())
    return _manifest(destination, "urllib3-community-compat", ["urllib3"])


_MARKER = '''from __future__ import annotations

import json
import os
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def emit(receiver_url: str | None = None, canary: str | None = None, run_id: str | None = None) -> bool:
    receiver_url = receiver_url or os.environ.get("ACTIVATION_RECEIVER_URL")
    canary = canary or os.environ.get("ACTIVATION_CANARY")
    run_id = run_id or os.environ.get("ACTIVATION_RUN_ID")
    if not receiver_url or not canary or not run_id:
        return False
    if urlparse(receiver_url).hostname not in {"receiver", "localhost", "127.0.0.1"}:
        return False
    payload = json.dumps({"run_id": run_id, "payload": canary, "source": "community-fork"}).encode("utf-8")
    request = Request(receiver_url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=1.0) as response:
            return 200 <= response.status < 300
    except OSError:
        return False
'''
