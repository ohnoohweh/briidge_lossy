#!/usr/bin/env bash
# Capture a non-systemd Fast VPS Triage report for one ObstacleBridge runtime.
#
# The normal `python -m obstacle_bridge` launcher supervises a separate bridge
# child. This script searches for the child, not the launcher, and deliberately
# omits process arguments from its report because they can contain secrets.

set -uo pipefail

sample_count=60
bridge_pid=""
report_dir=""
py_spy_seconds=120
capture_py_spy=1
declare -a sample_jobs=()

usage() {
    cat <<'EOF'
Usage: scripts/runtime_analysis.sh [--pid PID] [--samples COUNT] [--output-dir DIR]

Capture CPU, memory, I/O, context-switch, thread, host-pressure, socket,
deleted-open-file, global-CPU-leader, and Python flamegraph evidence for the
ObstacleBridge bridge process tree without using systemd. When --pid is
omitted, the script selects the sole matching bridge child. It exits rather
than guessing when several runtime children exist.

Options:
  --pid PID          Analyse this already-verified runtime PID.
  --samples COUNT    One-second samples per timed command (default: 60).
  --output-dir DIR   New directory for report files. Defaults to a timestamped
                     runtime-analysis-* directory in the current directory.
  --no-py-spy        Do not collect the 120-second py-spy flamegraph.
  -h, --help         Show this help text.

The report intentionally does not include process command lines or runtime
configuration. Run as the bridge service user for the best process visibility;
some socket and deleted-file details require additional privileges.

When py-spy is installed and permitted to attach, py-spy-flamegraph.svg is
captured for 120 seconds in parallel with the other measurements. This is
intended for a high-CPU incident. Use --no-py-spy for a shorter, lightweight
capture. The selected PID and every descendant present when the capture starts
are sampled individually. Children created later are recorded in the end tree
snapshot but have no retrospective timed samples.
EOF
}

fail() {
    printf 'runtime_analysis.sh: %s\n' "$*" >&2
    exit 2
}

require_positive_integer() {
    local value="$1"
    [[ "$value" =~ ^[1-9][0-9]*$ ]]
}

append_candidates() {
    local pattern="$1"
    local found_pid
    while IFS= read -r found_pid; do
        [[ -n "$found_pid" ]] || continue
        [[ "$found_pid" != "$$" && "$found_pid" != "$PPID" ]] || continue
        [[ -r "/proc/$found_pid/cmdline" ]] || continue
        candidate_pids["$found_pid"]=1
    done < <(pgrep -f "$pattern" 2>/dev/null || true)
}

safe_process_row() {
    local target_pid="$1"
    ps -p "$target_pid" -o pid=,ppid=,etimes=,stat=,pcpu=,pmem=,rss=,vsz=,nlwp=,comm=
}

write_once() {
    local filename="$1"
    shift
    if "$@" >"$report_dir/$filename" 2>&1; then
        return 0
    fi
    printf 'Command failed or was not permitted: %q\n' "$*" >>"$report_dir/$filename"
    return 0
}

start_sample() {
    local filename="$1"
    shift
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'Unavailable command: %s\n' "$1" >"$report_dir/$filename"
        return 0
    fi
    "$@" >"$report_dir/$filename" 2>&1 &
    sample_jobs+=("$!")
}

start_py_spy() {
    if (( ! capture_py_spy )); then
        printf 'py-spy capture disabled with --no-py-spy\n' >"$report_dir/py-spy-flamegraph.log"
        return 0
    fi
    if ! command -v py-spy >/dev/null 2>&1; then
        printf 'Unavailable command: py-spy\n' >"$report_dir/py-spy-flamegraph.log"
        return 0
    fi
    py-spy record --pid "$bridge_pid" --duration "$py_spy_seconds" --format flamegraph \
        --output "$report_dir/py-spy-flamegraph.svg" >"$report_dir/py-spy-flamegraph.log" 2>&1 &
    sample_jobs+=("$!")
}

write_global_cpu_consumers() {
    local filename="$1"
    if ps -eo pid,ppid,comm,%cpu,%mem --sort=-%cpu | head -20 >"$report_dir/$filename" 2>&1; then
        return 0
    fi
    printf 'Command failed or was not permitted: ps global CPU snapshot\n' >>"$report_dir/$filename"
    return 0
}

collect_process_tree() {
    local process_pid parent_pid
    local changed=1
    local -A parents=()
    local -A members=(["$bridge_pid"]=1)

    while read -r process_pid parent_pid; do
        [[ "$process_pid" =~ ^[1-9][0-9]*$ && "$parent_pid" =~ ^[0-9]+$ ]] || continue
        parents["$process_pid"]="$parent_pid"
    done < <(ps -eo pid=,ppid= 2>/dev/null || true)

    while (( changed )); do
        changed=0
        for process_pid in "${!parents[@]}"; do
            parent_pid="${parents[$process_pid]}"
            if [[ -n "${members[$parent_pid]:-}" && -z "${members[$process_pid]:-}" ]]; then
                members["$process_pid"]=1
                changed=1
            fi
        done
    done

    printf '%s\n' "${!members[@]}" | sort -n
}

write_per_process_snapshots() {
    local process_pid
    for process_pid in "${tracked_pids[@]}"; do
        write_once "process-status-pid${process_pid}.txt" cat "/proc/$process_pid/status"
        write_once "process-io-pid${process_pid}.txt" cat "/proc/$process_pid/io"
    done
}

stop_samples() {
    local job_pid
    for job_pid in "${sample_jobs[@]:-}"; do
        kill "$job_pid" 2>/dev/null || true
    done
}

trap 'stop_samples; exit 130' INT TERM

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pid)
            [[ $# -ge 2 ]] || fail '--pid requires a PID'
            bridge_pid="$2"
            shift 2
            ;;
        --samples)
            [[ $# -ge 2 ]] || fail '--samples requires a positive integer'
            require_positive_integer "$2" || fail '--samples requires a positive integer'
            sample_count="$2"
            shift 2
            ;;
        --output-dir)
            [[ $# -ge 2 ]] || fail '--output-dir requires a directory path'
            report_dir="$2"
            shift 2
            ;;
        --no-py-spy)
            capture_py_spy=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

if [[ -n "$bridge_pid" ]]; then
    [[ "$bridge_pid" =~ ^[1-9][0-9]*$ ]] || fail '--pid must be a positive integer'
    [[ -d "/proc/$bridge_pid" ]] || fail "PID $bridge_pid is not running"
else
    declare -A candidate_pids=()

    # Prefer the normal launcher-created child. The remaining patterns support
    # direct profiling/staging execution and the installed console entrypoint.
    append_candidates 'from obstacle_bridge\.bridge import main'
    if [[ ${#candidate_pids[@]} -eq 0 ]]; then
        append_candidates 'obstacle_bridge\.bridge_runner'
    fi
    if [[ ${#candidate_pids[@]} -eq 0 ]]; then
        append_candidates '(^|/)ObstacleBridge\.py([[:space:]]|$)'
    fi
    if [[ ${#candidate_pids[@]} -eq 0 ]]; then
        append_candidates '(^|[/[:space:]])ObstacleBridge([[:space:]]|$)'
    fi

    if [[ ${#candidate_pids[@]} -eq 0 ]]; then
        fail 'no ObstacleBridge bridge child found; supply --pid after checking pgrep -af "obstacle_bridge|ObstacleBridge"'
    fi
    if [[ ${#candidate_pids[@]} -gt 1 ]]; then
        printf 'Several possible ObstacleBridge runtime children were found. Re-run with --pid.\n' >&2
        while IFS= read -r candidate_pid; do
            safe_process_row "$candidate_pid" >&2 || true
        done < <(printf '%s\n' "${!candidate_pids[@]}" | sort -n)
        exit 2
    fi
    bridge_pid="${!candidate_pids[@]}"
fi

if [[ -z "$report_dir" ]]; then
    report_dir="./runtime-analysis-$(date -u +%Y%m%dT%H%M%SZ)-pid${bridge_pid}"
fi
[[ ! -e "$report_dir" ]] || fail "output path already exists: $report_dir"

umask 077
mkdir -p "$report_dir" || fail "could not create output directory: $report_dir"

printf 'ObstacleBridge Fast VPS Triage\n' >"$report_dir/README.txt"
printf 'UTC started: %s\n' "$(date -u +%FT%TZ)" >>"$report_dir/README.txt"
printf 'Bridge PID: %s\n' "$bridge_pid" >>"$report_dir/README.txt"
printf 'Samples: %s at one-second intervals\n' "$sample_count" >>"$report_dir/README.txt"
if (( capture_py_spy )); then
    printf 'py-spy flamegraph: 120 seconds when py-spy can attach\n' >>"$report_dir/README.txt"
else
    printf 'py-spy flamegraph: disabled\n' >>"$report_dir/README.txt"
fi
printf 'Process arguments and runtime configuration are deliberately omitted.\n' >>"$report_dir/README.txt"

mapfile -t tracked_pids < <(collect_process_tree)
(( ${#tracked_pids[@]} > 0 )) || fail 'could not enumerate the target process tree'
tracked_pid_list=$(IFS=,; printf '%s' "${tracked_pids[*]}")
printf 'Process-tree PIDs sampled at start: %s\n' "$tracked_pid_list" >>"$report_dir/README.txt"
printf '%s\n' "${tracked_pids[@]}" >"$report_dir/process-tree-pids-start.txt"

write_once environment.txt uname -a
{
    printf '\nlogical_cpus: '
    getconf _NPROCESSORS_ONLN 2>&1 || true
    printf '\npython_versions:\n'
    python3 -VV 2>&1 || true
    printf '\nprocess_tree_members_at_start:\n'
    ps -p "$tracked_pid_list" -o pid=,ppid=,etimes=,stat=,pcpu=,pmem=,rss=,vsz=,nlwp=,comm= 2>&1 || true
    printf '\nprocess_tree_without_arguments:\n'
    if command -v pstree >/dev/null 2>&1; then
        pstree -p "$bridge_pid" 2>&1 || true
    else
        printf 'pstree is unavailable\n'
    fi
} >>"$report_dir/environment.txt"

write_per_process_snapshots
write_once cpu-pressure.txt cat /proc/pressure/cpu
write_once sockets.txt ss -upnt
write_once interfaces.txt ip -s link
write_global_cpu_consumers global-cpu-consumers-start.txt

if command -v lsof >/dev/null 2>&1; then
    write_once deleted-open-files.txt lsof -p "$tracked_pid_list" +L1
else
    printf 'lsof is unavailable\n' >"$report_dir/deleted-open-files.txt"
fi

start_sample pidstat-process-tree.txt pidstat -u -r -d -w -p "$tracked_pid_list" 1 "$sample_count"
start_sample pidstat-threads-tree.txt pidstat -t -u -w -p "$tracked_pid_list" 1 "$sample_count"
for process_pid in "${tracked_pids[@]}"; do
    start_sample "top-threads-pid${process_pid}.txt" top -b -H -p "$process_pid" -d 1 -n "$sample_count"
done
start_sample mpstat.txt mpstat -P ALL 1 "$sample_count"
start_sample vmstat.txt vmstat 1 "$sample_count"
start_sample sar-network.txt sar -n DEV 1 "$sample_count"
start_py_spy

for job_pid in "${sample_jobs[@]:-}"; do
    wait "$job_pid" || true
done

if [[ ! -d "/proc/$bridge_pid" ]]; then
    printf 'The target PID exited during the capture. See timed command files for the partial result.\n' >>"$report_dir/README.txt"
fi

collect_process_tree >"$report_dir/process-tree-pids-end.txt"

write_global_cpu_consumers global-cpu-consumers-end.txt

printf 'Triage complete: %s\n' "$report_dir"
printf 'Review README.txt, process-tree-pids-{start,end}.txt, global-cpu-consumers-{start,end}.txt, py-spy-flamegraph.svg, pidstat-*-tree.txt, top-threads-pid*.txt, mpstat.txt, vmstat.txt, cpu-pressure.txt, and deleted-open-files.txt.\n'
