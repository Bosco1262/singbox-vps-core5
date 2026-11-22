# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sbox5.cli import main

raise SystemExit(main())
