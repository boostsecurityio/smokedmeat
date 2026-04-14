Output smokedmeat-demo.gif

Set LoopOffset 35%

Set FontSize 19
Set Width 1900
Set Height 1200
Set Padding 8
Set Margin 8
Set WindowBar Colorful

Set TypingSpeed 80ms
Set CursorBlink false

Set Shell zsh

Type "git clone https://github.com/boostsecurityio/smokedmeat.git"
Enter
Wait+Screen@30s /Resolving deltas:|Checking connectivity|done\./
Sleep 250ms

Type "cd smokedmeat"
Enter
Sleep 500ms

Type "make quickstart"
Enter
Wait+Screen@30s /Paste a Personal Access Token/
Sleep 1s

Down
Enter
Wait+Screen@10s /Organization/
Sleep 800ms

Enter
Type "whooli"
Sleep 500ms
Enter

Wait+Screen@60s /Bash injection/
Sleep 1s

Type "1"
Wait+Screen@10s /Step 1\/3/
Sleep 500ms

Enter
Wait+Screen@10s /Step 2\/3/
Sleep 500ms

Enter
Wait+Screen@10s /Step 3\/3/
Sleep 500ms

Enter
Wait+Screen@45s /Express complete/
Sleep 1s

Down
Down
Down
Sleep 800ms
Wait+Screen@15s /App ID:/
Sleep 500ms

Type "p"
Wait+Screen@20s /GitHub App pivot successful|PRIVATE repos|Active token swapped/
Sleep 2s

Type "q"
Sleep 500ms
