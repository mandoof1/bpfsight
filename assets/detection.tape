# Detections fire live: reverse-shell redirect, curl|sh, base64 -d, recon,
# and the shipped rules/metasploit.yml matching a connect to 4444.
Set Width 1360
Set Height 700
Set Theme "Dracula"
Set FontSize 13
Set TypingSpeed 8ms
Set MarginFill "#101418"
Set Margin 24
Type "DB=/tmp/detection-demo.sqlite; sudo -n rm -f $DB $DB-wal $DB-shm || true"
Enter
Sleep 500ms
Type "sudo -n target/release/bpfsight run --db $DB --rules-dir rules &"
Enter
Sleep 1500ms
Type "bash -c 'echo AAA | base64 -d >/dev/null; true <> /dev/tcp/127.0.0.1/4444' 2>/dev/null; id >/dev/null"
Enter
Sleep 1200ms
Type "python3 tools/demo-connect.py"
Enter
Sleep 5200ms
Output "assets/detection.gif"
