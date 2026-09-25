#!/usr/bin/env sh
set -eu

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

case_dir=cases/software-engineering/C31/se-dependency-upgrade-v1
run_workspace="artifacts/$run_id/workspace"
if [ -e "$run_workspace" ]; then
  echo "run workspace already exists: $run_workspace" >&2
  exit 2
fi
mkdir -p "$run_workspace"
cp -R "$case_dir/repository/worktree/." "$run_workspace/"
CASE_MANIFEST_PATH="$case_dir/evaluation/manifest.json" RUN_WORKSPACE="$run_workspace" \
  python3 "$case_dir/environment/service_entrypoint.py" provision
RUN_WORKSPACE="./$run_workspace" FIXTURE="$fixture" \
  docker compose -f compose.c31.yaml up -d workspace
printf '%s\n' "runtime is external; configure it with integrations/<runtime>/integration.json"
printf '%s\n' "G=$g_mode"
printf '%s\n' "after the run: python3 scripts/c31_evaluate_run.py --workspace $run_workspace --manifest $case_dir/evaluation/manifest.json --run-id $run_id"
