# The stats subcommand: event volume by kind, drop accounting, alerts by rule.
# Fresh db file so the numbers correspond to exactly one capture run.
Set Width 1200
Set Height 640
Set Theme "Dracula"
Set FontSize 13
Set TypingSpeed 8ms
Set MarginFill "#101418"
Set Margin 24
Type "DB=/tmp/stats-demo.sqlite; sudo -n rm -f $DB || true"
Enter
Sleep 600ms
Type "sudo -n target/release/bpfsight run --db $DB --rules-dir rules --duration 5 >/dev/null"
Enter
Sleep 6500ms
Type "target/release/bpfsight stats --db $DB"
Enter
Sleep 1500ms
Output "assets/stats.gif"
