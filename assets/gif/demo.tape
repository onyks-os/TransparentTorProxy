# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
#
# Records assets/gif/demo.gif, the README demo, from a real session.
#
# It drives the installed `ttp` against the live network, so the host does go
# through Tor while it runs and is back in cleartext when it ends. Run it as
# root so that the `sudo` it types never stops at a password prompt VHS cannot
# answer:
#
#   sudo vhs assets/gif/demo.tape && sudo chown "$USER": assets/gif/demo.gif
#
# Nothing here is staged: what the GIF shows is what TTP printed.

Output assets/gif/demo.gif

Require ttp

Set Shell bash
Set FontSize 22
Set Width 1200
Set Height 720
Set Padding 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "export PS1='> ' && clear"
Enter
Show

Type "sudo ttp start"
Sleep 400ms
Enter
Wait@120s />\s*$/
Sleep 2.5s

Type "sudo ttp check"
Sleep 400ms
Enter
Wait@60s />\s*$/
Sleep 3s

Type "sudo ttp stop"
Sleep 400ms
Enter
Wait@60s />\s*$/
Sleep 3s
