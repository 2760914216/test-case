# Generated Artifacts

Runtime outputs belong under `artifacts/<run-id>/` and are ignored by Git.
Release verification evidence belongs under `artifacts/verification/` and is
tracked when it contains no credentials or model API secrets.

Required Ubuntu Docker evidence file:

```json
{
  "os": "Ubuntu 26.04 LTS",
  "docker_version": "record the observed version",
  "compose_version": "record the observed version",
  "base_image_digest": "python@sha256:<64 lowercase hexadecimal characters>",
  "compose_config_ok": true,
  "build_ok": true,
  "smoke_ok": true
}
```

Do not create this file before the commands have actually succeeded.
