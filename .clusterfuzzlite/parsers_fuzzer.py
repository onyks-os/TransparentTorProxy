#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
import sys

import atheris

with atheris.instrument_imports():
    from fuzzing.parsers import exercise_bytes

if __name__ == "__main__":
    atheris.Setup(sys.argv, exercise_bytes)
    atheris.Fuzz()
