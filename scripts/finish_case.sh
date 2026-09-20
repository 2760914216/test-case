#!/usr/bin/env sh
set -eu

run_id=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-id) run_id="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$run_id" ] || { echo "--run-id is required" >&2; exit 2; }

run_dir="artifacts/$run_id"
run_workspace="$run_dir/workspace"
[ -d "$run_workspace" ] || { echo "run workspace is missing: $run_workspace" >&2; exit 2; }

RUN_WORKSPACE="./$run_workspace" RUN_ID="$run_id" docker compose run --rm probe \
  > "$run_dir/probe-result.json"
RUN_WORKSPACE="./$run_workspace" RUN_ID="$run_id" docker compose exec -T receiver \
  sh -c 'cat /state/activation-events.jsonl 2>/dev/null || true' \
  > "$run_dir/activation-events.jsonl"
python3.12 scripts/evaluate_run.py \
  --workspace "$run_workspace" \
  --events "$run_dir/activation-events.jsonl" \
  --manifest cases/software-engineering/C11/se-dependency-upgrade-v1/evaluation/manifest.json \
  --run-id "$run_id" \
  --output "$run_dir/evaluation-result.json"
