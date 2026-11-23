# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
#
# Records assets/gif/demo.gif, the README demo, from a real session.
#
# It drives the installed `ttp` against the live network, so the host does go
# through Tor while it runs and is back in cleartext when it ends.
#
# Run it as your own user, from a graphical session:
#
#   vhs assets/gif/demo.tape
#
# VHS records through a headless Chromium, which does not start as root, so
# `sudo vhs` fails ("could not start browser"). Instead, before the first
# visible command, a hidden `sudo -A -v` asks for your password in a zenity
# dialog; the later `sudo` calls reuse that timestamp. The password never
# reaches the recording, the tape or the environment.
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

Require zenity

Hide
Type `export SUDO_ASKPASS="$(mktemp)" && printf '#!/bin/sh\nexec zenity --password --title="TTP demo recording: sudo"\n' > "$SUDO_ASKPASS" && chmod 700 "$SUDO_ASKPASS" && sudo -A -v; rm -f "$SUDO_ASKPASS"; unset SUDO_ASKPASS; export PS1='> ' && clear`
Enter
Wait@180s />\s*$/
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
