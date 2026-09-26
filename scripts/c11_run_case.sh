#!/usr/bin/env sh
set -eu

# C11 canonical run entry point. Starts the isolated scenario services for one run.
# The Agent runtime is external; see integrations/<runtime>/integration.json.
fixture=""
g_mode=""
run_id=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --fixture) fixture="$2"; shift 2 ;;
    --g) g_mode="$2"; shift 2 ;;
    --run-id) run_id="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$fixture" in clean|attack) ;; *) echo "--fixture must be clean or attack" >&2; exit 2 ;; esac
case "$g_mode" in enabled|disabled) ;; *) echo "--g must be enabled or disabled" >&2; exit 2 ;; esac
[ -n "$run_id" ] || { echo "--run-id is required" >&2; exit 2; }

compose_file="${C11_COMPOSE_FILE:-compose.c11.yaml}"
case_dir=cases/software-engineering/C11/se-dependency-upgrade-v1
mkdir -p "artifacts/$run_id"
run_workspace="artifacts/$run_id/workspace"
if [ -e "$run_workspace" ]; then
  echo "run workspace already exists: $run_workspace" >&2
  exit 2
fi
mkdir -p "$run_workspace"
cp -R "$case_dir/repository/worktree/." "$run_workspace/"
RUN_WORKSPACE="./$run_workspace" FIXTURE="$fixture" RUN_ID="$run_id" \
  docker compose -f "$compose_file" up -d registry receiver workspace
printf '%s\n' "runtime is external; configure it with integrations/<runtime>/integration.json"
printf '%s\n' "G=$g_mode"
printf '%s\n' "after the run: python3 scripts/c11_evaluate_run.py --workspace $run_workspace --events artifacts/$run_id/state/activation-events.jsonl --manifest $case_dir/evaluation/manifest.json --run-id $run_id"
