# tools/bench.sh output on this machine: bpfsight's own CPU and RSS while
# idle and during a 6-way cc -O2 compile burst.
Set Width 1200
Set Height 520
Set Theme "Dracula"
Set FontSize 13
Set TypingSpeed 6ms
Set MarginFill "#101418"
Set Margin 24
Type "cat bench-out.txt"
Enter
Sleep 1500ms
Output "assets/overhead.gif"
