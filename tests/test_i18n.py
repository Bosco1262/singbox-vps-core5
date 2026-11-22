# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbox5.i18n import get_language, normalize_language, resolve_language, set_language, tr


class LanguageResolutionTests(unittest.TestCase):
    def test_explicit_argument_wins_over_environment(self):
        with patch.dict(os.environ, {"LC_ALL": "", "LC_MESSAGES": "", "LANG": "en_US.UTF-8", "LANGUAGE": ""}):
            self.assertEqual(resolve_language(["--lang", "zh-CN"]), "zh-CN")
            self.assertEqual(resolve_language(["install", "-l", "en"]), "en")
            self.assertEqual(resolve_language(["--language=zh_CN"]), "zh-CN")
            self.assertEqual(resolve_language(["-l=zh"]), "zh-CN")

    def test_system_detection_is_used_without_explicit_argument(self):
        with patch.dict(os.environ, {"LC_ALL": "", "LC_MESSAGES": "", "LANG": "zh_CN.UTF-8", "LANGUAGE": ""}):
            self.assertEqual(resolve_language(["install"]), "zh-CN")
        with patch.dict(os.environ, {"LC_ALL": "", "LC_MESSAGES": "", "LANG": "en_US.UTF-8", "LANGUAGE": ""}):
            self.assertEqual(resolve_language(["install"]), "en")

    def test_english_is_the_guaranteed_fallback(self):
        with patch.dict(os.environ, {"LC_ALL": "", "LC_MESSAGES": "", "LANG": "", "LANGUAGE": ""}), \
                patch("sbox5.i18n.locale.getdefaultlocale", return_value=(None, None)):
            self.assertEqual(resolve_language(["install"]), "en")

    def test_unsupported_values_normalize_to_none(self):
        self.assertIsNone(normalize_language("fr-FR"))
        self.assertIsNone(normalize_language(""))
        self.assertIsNone(normalize_language(None))

    def test_output_switches_with_the_active_language(self):
        set_language("zh-CN")
        self.assertEqual(tr("Warning", "警告"), "警告")
        set_language("en")
        self.assertEqual(tr("Warning", "警告"), "Warning")
        set_language("unsupported")
        self.assertEqual(get_language(), "en")


if __name__ == "__main__":
    unittest.main()
