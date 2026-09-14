# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Offensive leak verification probes.

Excluded from the default suite by ``--ignore=tests/leak`` in ``pyproject.toml``
because every probe here needs a live TTP session and real network egress. They
are run by hand through ``make test-leak-ip`` / ``-dns`` / ``-webrtc``.

The verdict logic they depend on lives in :mod:`tests.leak.oracle` and *is* in
the default suite, via ``tests/test_leak_oracle.py`` - deliberately, so that the
part which decides pass or fail is tested on every commit even though the probes
around it are not.
"""
