#!/usr/bin/env sh
set -eu

base_image="${PYTHON_IMAGE:-python:3.12.11-slim}"
docker pull "$base_image"
base_digest="$(docker image inspect "$base_image" --format '{{index .RepoDigests 0}}')"
case "$base_digest" in
  *@sha256:*) ;;
  *) echo "base image has no immutable RepoDigest: $base_image" >&2; exit 1 ;;
esac
docker compose build --build-arg PYTHON_IMAGE="$base_digest"
printf '%s\n' "base_image_digest=$base_digest"
