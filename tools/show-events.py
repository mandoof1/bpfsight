#!/usr/bin/env python3
"""Pretty-print captured events from a bpfsight JSONL sink."""
import json, sys
want = sys.argv[2] if len(sys.argv) > 2 else None
n = 0
for line in open(sys.argv[1]):
    e = json.loads(line)
    if want and e["kind"] != want:
        continue
    print(f"{e['ts'][11:23]} {e['kind']:<8} {e['pid']:>6} {e['comm']:<14} "
          f"{e['path'][:44]} {e['args'][:30]}")
    n += 1
    if n >= 12:
        break
