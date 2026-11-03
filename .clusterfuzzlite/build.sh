#!/bin/bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
set -euo pipefail
python3 -m pip install --require-hashes --no-deps --only-binary=:all: -r requirements/tools.txt
python3 -m pip install --require-hashes --no-deps --no-build-isolation -r requirements/runtime.txt
python3 -m build --no-isolation --wheel --outdir /tmp/ttp-wheel
python3 -m installer /tmp/ttp-wheel/*.whl
pyinstaller --distpath "$OUT" --onefile --paths . --name parsers_fuzzer.pkg .clusterfuzzlite/parsers_fuzzer.py
# Pure Python target: no sanitizer LD_PRELOAD (as required by the upstream guide).
cat > "$OUT/parsers_fuzzer" <<'WRAPPER'
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
exec "$(dirname "$0")/parsers_fuzzer.pkg" "$@"
WRAPPER
chmod +x "$OUT/parsers_fuzzer"
python3 - <<'PY'
import os
import zipfile
from pathlib import Path
with zipfile.ZipFile(Path(os.environ['OUT']) / 'parsers_fuzzer_seed_corpus.zip', 'w') as archive:
    for seed in Path('.clusterfuzzlite/corpus').iterdir():
        archive.write(seed, seed.name)
PY
