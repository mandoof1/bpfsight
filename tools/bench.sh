#!/usr/bin/env bash
# Measure bpfsight's own overhead while idle and during a compile burst.
# Usage: sudo tools/bench.sh [seconds-per-phase]   (default 15)
set -u
BIN=${BIN:-target/release/bpfsight}
PHASE=${1:-15}
DB=$(mktemp /tmp/bpfsight-bench-XXXX.sqlite)

build_burst() {
  awk 'BEGIN{for(i=0;i<3000;i++) printf "int f%d(int x){return x+%d;}\n", i, i}' > /tmp/bpfsight-burst.c
}

sample() { # pid -> prints "<cpu-of-one-core%> <rss-kb>"
  local pid=$1
  local s1 s2
  s1=$(awk '{print $14+$15}' /proc/$pid/stat)
  sleep "$PHASE"
  s2=$(awk '{print $14+$15}' /proc/$pid/stat)
  local hz; hz=$(getconf CLK_TCK)
  local ticks=$((s2 - s1))
  local cpu rss
  cpu=$(awk -v t="$ticks" -v hz="$hz" -v p="$PHASE" 'BEGIN{printf "%.2f", (t/hz)/p*100}')
  rss=$(awk '/VmRSS/{print $2}' /proc/$pid/status)
  echo "$cpu $rss"
}

echo "== idle phase: ${PHASE}s =="
"$BIN" run --db "$DB" --duration $((PHASE*2+4)) --quiet >/tmp/bench-run.log 2>&1 &
sleep 1
PID=$(pgrep -f "$BIN run" | head -1)
IDLE=$(sample "$PID")
echo "idle: cpu=${IDLE% *}% rss=${IDLE#* }kB"

echo "== compile burst: 6x cc -O2 over 3000-function TU, ${PHASE}s =="
build_burst
PIDS=()
END=$((SECONDS+PHASE))
for i in 1 2 3 4 5 6; do
  ( while [ $SECONDS -lt $END ]; do cc -O2 -c /tmp/bpfsight-burst.c -o /dev/null; done ) &
  PIDS+=($!)
done
BURST=$(sample "$PID")
wait "${PIDS[@]}" 2>/dev/null
echo "burst: cpu=${BURST% *}% rss=${BURST#* }kB"
pkill -f "$BIN run"; sleep 1
rm -f "$DB" /tmp/bpfsight-burst.c
echo "peak RSS:"; grep -h VmHWM /tmp/bench-run.log 2>/dev/null || true
