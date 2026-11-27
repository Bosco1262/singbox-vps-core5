# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "sb.sh"


def find_shell() -> str:
    shell = shutil.which("sh")
    if shell:
        return shell
    if os.name == "nt":
        for candidate in (
            r"C:\Program Files\Git\bin\sh.exe",
            r"C:\Program Files\Git\usr\bin\sh.exe",
            r"C:\Program Files (x86)\Git\bin\sh.exe",
        ):
            if Path(candidate).is_file():
                return candidate
    return ""


class ShellConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SCRIPT.read_text(encoding="utf-8")
        cls.shell = find_shell()

    def test_uses_posix_shell_and_strict_defaults(self):
        self.assertTrue(self.text.startswith("#!/bin/sh\n"))
        self.assertIn("set -u", self.text)
        self.assertIn("umask 077", self.text)

    def test_has_no_direct_privileged_or_remote_execution(self):
        forbidden = re.compile(
            r"^\s*(eval|curl|wget|systemctl|rc-service|iptables|nft|sing-box)\b",
            re.MULTILINE,
        )
        matches = [match.group(0).strip() for match in forbidden.finditer(self.text)]
        self.assertEqual(matches, [])
        self.assertNotRegex(self.text, r"\b(?:bash|sh)\s+-c\b")

    def test_syntax_is_valid(self):
        if not self.shell:
            self.skipTest("no POSIX shell available")
        result = subprocess.run(
            [self.shell, "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
