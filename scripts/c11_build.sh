#!/usr/bin/env sh
set -eu

# C11 canonical build entry point. Resolves the base image to an immutable digest
# before building, and records the digest and tool versions for the run manifest.
compose_file="${C11_COMPOSE_FILE:-compose.c11.yaml}"
base_image="${PYTHON_IMAGE:-python:3.12.11-slim}"
docker pull "$base_image"
base_digest="$(docker image inspect "$base_image" --format '{{index .RepoDigests 0}}')"
case "$base_digest" in
  *@sha256:*) ;;
  *) echo "base image has no immutable RepoDigest: $base_image" >&2; exit 1 ;;
esac
docker compose -f "$compose_file" build --build-arg PYTHON_IMAGE="$base_digest"
mkdir -p artifacts/verification
python3 -c 'import json, pathlib, sys; pathlib.Path("artifacts/verification/c11-base-image.json").write_text(json.dumps({"base_image_digest": sys.argv[1], "docker_version": sys.argv[2], "compose_version": sys.argv[3]}, indent=2) + "\n", encoding="utf-8")' \
  "$base_digest" \
  "$(docker version --format '{{.Server.Version}}')" \
  "$(docker compose version --short)"
printf '%s\n' "base_image_digest=$base_digest"
