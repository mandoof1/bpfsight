# Live event stream: 4 seconds of capture on a busy desktop while three
# commands run (id, /usr/bin/true, a shell redirect), then the exec rows
# from the JSONL sink.
Set Width 1360
Set Height 660
Set Theme "Dracula"
Set FontSize 13
Set TypingSpeed 8ms
Set MarginFill "#101418"
Set Margin 24
Type "DB=/tmp/events-demo.sqlite; sudo -n rm -f $DB $DB-wal $DB-shm || true"
Enter
Sleep 500ms
Type "sudo -n target/release/bpfsight run --db $DB --jsonl /tmp/ev.jsonl --duration 4 --quiet &"
Enter
Sleep 1200ms
Type "id >/dev/null; /usr/bin/true exec-trigger; echo x > /tmp/ev-probe.txt"
Enter
Sleep 4500ms
Type "wait; python3 tools/show-events.py /tmp/ev.jsonl exec"
Enter
Sleep 1500ms
Output "assets/events.gif"
